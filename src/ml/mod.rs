//! ML module
//!
//! Machine learning for anomaly detection using Candle

pub mod candle_backend;
pub mod features;
pub mod anomaly;
pub mod scorer;
pub mod models;

/// Marker struct for module tests
pub struct MlMarker;
