use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Babeltrace(#[from] babeltrace2_sys::Error),

    #[error("Encountered an ingest client initialization error. {0}")]
    IngestClientInitialization(#[from] modality_ingest_client::IngestClientInitializationError),

    #[error("Encountered an ingest client error. {0}")]
    Ingest(#[from] modality_ingest_client::IngestError),

    #[error("Encountered an ingest client error. {0}")]
    DynamicIngest(#[from] modality_ingest_client::dynamic::DynamicIngestError),

    #[error(transparent)]
    Auth(#[from] crate::auth::AuthTokenError),

    #[error(
        "Event attribute key prefix cannot start or end with the reserved delimeter '.' character"
    )]
    InvalidAttrKeyPrefix,

    #[error("The available stream properties doesn't contain a stream ID matching the provided merge-stream-id")]
    MergeStreamIdNotFound,
}
