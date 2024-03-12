use std::fmt::Display;
use std::fmt::Formatter;
use std::hash::Hash;
use std::sync::Arc;

use apollo_compiler::ast;
use apollo_compiler::validation::DiagnosticList;
use apollo_compiler::ExecutableDocument;
use http::StatusCode;
use lru::LruCache;
use tokio::sync::Mutex;

use crate::context::OPERATION_KIND;
use crate::context::OPERATION_NAME;
use crate::plugins::authorization::AuthorizationPlugin;
use crate::query_planner::OperationKind;
use crate::services::SupergraphRequest;
use crate::services::SupergraphResponse;
use crate::spec::Query;
use crate::spec::Schema;
use crate::Configuration;
use crate::Context;

// new temporary imports
use std::collections::HashMap;
use serde::Deserialize;
use serde::Serialize;

/// [`Layer`] for QueryAnalysis implementation.
#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub(crate) struct QueryAnalysisLayer {
    pub(crate) schema: Arc<Schema>,
    configuration: Arc<Configuration>,
    cache: Arc<Mutex<LruCache<QueryAnalysisKey, (Context, ParsedDocument)>>>,
    enable_authorization_directives: bool,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct QueryAnalysisKey {
    query: String,
    operation_name: Option<String>,
}

// probably need to move these somewhere else

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
#[serde(rename_all = "camelCase")]
/// A list of fields that will be resolved
/// for a given type
pub(crate) struct ExperimentalReferencedFieldsForType {
    /// names of the fields queried
    #[serde(default)]
    pub(crate) field_names: Vec<String>,
    /// whether the field is an interface
    #[serde(default)]
    pub(crate) is_interface: bool,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
#[serde(rename_all = "camelCase")]
/// UsageReporting fields that will be used to send stats to uplink/studio. This version
/// of the data is generated using apollo-rs instead of the bridge query planner.
pub(crate) struct ExperimentalUsageReporting {
    /// The `stats_report_key` is a unique identifier derived from schema and query.
    /// Metric data sent to Studio must be aggregated
    /// via grouped key of (`client_name`, `client_version`, `stats_report_key`).
    pub(crate) stats_report_key: String,
    /// a list of all types and fields referenced in the query
    #[serde(default)]
    pub(crate) referenced_fields_by_type: HashMap<String, ExperimentalReferencedFieldsForType>,
}

impl QueryAnalysisLayer {
    pub(crate) async fn new(schema: Arc<Schema>, configuration: Arc<Configuration>) -> Self {
        let enable_authorization_directives =
            AuthorizationPlugin::enable_directives(&configuration, &schema).unwrap_or(false);
        Self {
            schema,
            cache: Arc::new(Mutex::new(LruCache::new(
                configuration
                    .supergraph
                    .query_planning
                    .cache
                    .in_memory
                    .limit,
            ))),
            enable_authorization_directives,
            configuration,
        }
    }

    pub(crate) fn parse_document(&self, query: &str) -> ParsedDocument {
        Query::parse_document(query, self.schema.api_schema(), &self.configuration)
    }

    pub(crate) async fn supergraph_request(
        &self,
        request: SupergraphRequest,
    ) -> Result<SupergraphRequest, SupergraphResponse> {
        let query = request.supergraph_request.body().query.as_ref();

        if query.is_none() || query.unwrap().trim().is_empty() {
            let errors = vec![crate::error::Error::builder()
                .message("Must provide query string.".to_string())
                .extension_code("MISSING_QUERY_STRING")
                .build()];
            u64_counter!(
                "apollo_router_http_requests_total",
                "Total number of HTTP requests made.",
                1,
                status = StatusCode::BAD_REQUEST.as_u16() as i64,
                error = "Must provide query string"
            );

            return Err(SupergraphResponse::builder()
                .errors(errors)
                .status_code(StatusCode::BAD_REQUEST)
                .context(request.context)
                .build()
                .expect("response is valid"));
        }

        let op_name = request.supergraph_request.body().operation_name.clone();
        let query = request
            .supergraph_request
            .body()
            .query
            .clone()
            .expect("query presence was already checked");
        let entry = self
            .cache
            .lock()
            .await
            .get(&QueryAnalysisKey {
                query: query.clone(),
                operation_name: op_name.clone(),
            })
            .cloned();

        let (context, doc) = match entry {
            None => {
                let span = tracing::info_span!("parse_query", "otel.kind" = "INTERNAL");
                let doc = span.in_scope(|| self.parse_document(&query));
                // doc here contains the AST

                let context = Context::new();

                let operation = doc.executable.get_operation(op_name.as_deref()).ok();
                let operation_name = operation
                    .as_ref()
                    .and_then(|operation| operation.name.as_ref().map(|s| s.as_str().to_owned()));

                context.insert(OPERATION_NAME, operation_name).unwrap();
                let operation_kind = operation.map(|op| OperationKind::from(op.operation_type));
                context
                    .insert(OPERATION_KIND, operation_kind.unwrap_or_default())
                    .expect("cannot insert operation kind in the context; this is a bug");

                if self.enable_authorization_directives {
                    AuthorizationPlugin::query_analysis(
                        &query,
                        &self.schema,
                        &self.configuration,
                        &context,
                    );
                }

                (*self.cache.lock().await).put(
                    QueryAnalysisKey {
                        query,
                        operation_name: op_name,
                    },
                    (context.clone(), doc.clone()),
                );

                (context, doc)
            }
            Some(c) => c,
        };

        let cloned_doc = doc.clone();

        request.context.extend(&context);
        request
            .context
            .extensions()
            .lock()
            .insert::<ParsedDocument>(doc);

        // temporary hacky code starts here

        // this works for top level fields

        // println!("executable anonymous_operation: {:?}", &cloned_doc.executable.anonymous_operation);
        // println!("executable fragments: {:?}", &cloned_doc.executable.fragments);
        // println!("executable named_operations: {:?}", &cloned_doc.executable.named_operations);

        let api_schema = self.schema.api_schema(); // todo: can we just use self.schema?

        let (_name, operation) = cloned_doc.executable.named_operations.first().unwrap();
        // println!("executable operation name: {}", name);
        // println!("executable operation: {}", operation);
        // println!("executable operation type: {}", operation.operation_type);
        // println!("executable operation selection set type: {}", operation.selection_set.ty);

        let query_fields = operation.selection_set.selections
            .iter()
            .map(|x| x.as_field().unwrap().name.to_string())
            .collect();

        let mut ref_fields = HashMap::from([
            (operation.selection_set.ty.to_string(), ExperimentalReferencedFieldsForType {
                field_names: query_fields,
                is_interface: false,
            })
        ]);

        /* 
        for var in operation.variables.iter() {
            println!("var: {}", var.name);
        }
        */

        for selection in operation.selection_set.selections.iter() {
            let field = selection.as_field().unwrap();

            /*
            println!("field name: {}", field.name);
            println!("field type: {}", field.definition.ty);
            println!("field selection set type: {}", field.selection_set.ty);
            */

            let child_fields = field.selection_set.selections
                .iter()
                .map(|x| x.as_field().unwrap().name.to_string())
                .collect();
            
            ref_fields.insert(field.selection_set.ty.to_string(), ExperimentalReferencedFieldsForType {
                field_names: child_fields,
                is_interface: false, // todo use value from below (or maybe the bridge always sends "false"?)
            });

            for field_selection in field.selection_set.selections.iter() {
                let child_field = field_selection.as_field().unwrap();
                let child_field_type_name = child_field.definition.ty.to_string();
                let child_field_schema_type = api_schema.definitions.types.get(child_field_type_name.as_str());
                if let Some(unwrapped) = child_field_schema_type {
                    if let apollo_compiler::schema::ExtendedType::Interface (x) = unwrapped {
                        println!("found interface object {} of type {}", child_field.name.as_str(), x.name.as_str());
                    }
                }
            }

            for field_arg in field.arguments.iter() {
                println!("field_arg name: {}", field_arg.name);
                println!("field_arg value: {:?}", field_arg.value);

                if let Some(field_arg_var) = field_arg.value.as_variable() {
                    println!("found variable with name {}", field_arg_var.as_str());

                    for (var_name, var_val) in request.supergraph_request.body().variables.iter() {
                        if var_name.as_str() == field_arg_var.as_str() {
                            println!("var val: {}", var_val);
                        }
                    }
                }

                for field_def_arg in field.definition.arguments.iter() {
                    if field_def_arg.name == field_arg.name {
                        println!("field_def_arg type: {}", field_def_arg.ty);
                        println!("field_def_arg default: {:?}", field_def_arg.default_value);

                        if field_def_arg.ty.is_named() {
                            let schema_type = api_schema.definitions.types.get(field_def_arg.ty.inner_named_type().as_str());
                            if let Some(unwrapped) = schema_type {
                                if let apollo_compiler::schema::ExtendedType::InputObject (x) = unwrapped {
                                    println!("found input object argument, listing all fields");
                                    for (name, _def) in x.fields.iter() {
                                        println!("field name: {}", name.to_string());
                                        // println!("def name: {}", def.name.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // println!("ast: {}",  &cloned_doc.ast);

        let definitions = cloned_doc.ast.definitions.clone();
        let operation_def = definitions[0].as_operation_definition().unwrap().clone();

        let operation_body = operation_def.to_string();
        let operation_name = operation_def.name.as_ref().unwrap().to_string();
        // println!("operation_body: {}", operation_body);
        // println!("operation_name: {}", operation_name);

        let whitespace_regex = regex::Regex::new(r"\s+").unwrap();
        let stripped_body = whitespace_regex.replace_all(&operation_body, " ").to_string();
        // println!("stripped_body: {}", stripped_body);

        request.context.extensions().lock().insert(ExperimentalUsageReporting {
            stats_report_key: format!("# {}\n{}", operation_name, stripped_body),
            referenced_fields_by_type: ref_fields,
        });

        // temporary hacky code ends here

        Ok(SupergraphRequest {
            supergraph_request: request.supergraph_request,
            context: request.context,
        })
    }
}

pub(crate) type ParsedDocument = Arc<ParsedDocumentInner>;

#[derive(Debug, Default)]
pub(crate) struct ParsedDocumentInner {
    pub(crate) ast: ast::Document,
    pub(crate) executable: Arc<ExecutableDocument>,
    pub(crate) parse_errors: Option<DiagnosticList>,
    pub(crate) validation_errors: Option<DiagnosticList>,
}

impl Display for ParsedDocumentInner {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Hash for ParsedDocumentInner {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.ast.hash(state);
    }
}

impl PartialEq for ParsedDocumentInner {
    fn eq(&self, other: &Self) -> bool {
        self.ast == other.ast
    }
}

impl Eq for ParsedDocumentInner {}
