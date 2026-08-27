"""Forge bounded worker SDK and fail-closed materializer foundation.

Nothing in this package is a production neural-analysis validation or a device
control implementation. The public surface deliberately contains no direct
register command API.
"""

from .algorithms import (
    AnalysisContinuityError,
    BandMeasurement,
    FixedTemplateClassifier,
    LfpBand,
    LfpBandAnalyzer,
    LfpConfig,
    StreamingLfpBandAnalyzer,
    SpikeClassification,
    SpikeEvent,
    TemplateConfig,
    ThresholdConfig,
    ThresholdCrossingDetector,
    WindowedBandMeasurement,
)
from .analysis_registration import (
    AnalysisWorkerRegisterRequestV1,
    AnalysisWorkerRegisterResponseV1,
    RegisteredObserver,
    RegistrationCodecError,
    RegistrationError,
    RegistrationRejected,
    register_observer,
)
from .sdk import (
    AnalysisAnnotation,
    AnalysisWorker,
    BoundedConsumer,
    FrozenStimIntentContext,
    SampleBlock,
    StimIntentV1,
)
from .shared_ring import (
    LiveRingError,
    RingSnapshot,
    RingSnapshotError,
    RingSnapshotRecord,
    WindowsMappedRingConsumer,
    native_live_available,
    parse_ring_snapshot,
)

__all__ = [
    "AnalysisAnnotation",
    "AnalysisContinuityError",
    "AnalysisWorkerRegisterRequestV1",
    "AnalysisWorkerRegisterResponseV1",
    "AnalysisWorker",
    "BandMeasurement",
    "BoundedConsumer",
    "FrozenStimIntentContext",
    "FixedTemplateClassifier",
    "LfpBand",
    "LfpBandAnalyzer",
    "LfpConfig",
    "StreamingLfpBandAnalyzer",
    "LiveRingError",
    "RingSnapshot",
    "RingSnapshotError",
    "RingSnapshotRecord",
    "RegisteredObserver",
    "RegistrationCodecError",
    "RegistrationError",
    "RegistrationRejected",
    "SampleBlock",
    "SpikeClassification",
    "SpikeEvent",
    "StimIntentV1",
    "TemplateConfig",
    "ThresholdConfig",
    "ThresholdCrossingDetector",
    "WindowedBandMeasurement",
    "WindowsMappedRingConsumer",
    "native_live_available",
    "parse_ring_snapshot",
    "register_observer",
]
