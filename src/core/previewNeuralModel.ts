export type PreviewNeuralSourceKind = "canonical-synthetic" | "nwb-derived-reconstruction";

export interface PreviewNeuralSample {
  lfp: number;
  spike: number;
  noise: number;
  wideband: number;
}

/** Random-access source used only to author bounded mock Preview frames. */
export interface PreviewNeuralModel {
  readonly sourceKind: PreviewNeuralSourceKind;
  readonly channelCount: number | null;
  readonly scenarioId: string;
  readonly scenarioHash: string;
  readonly sampleRateHz: number;
  readonly previewMicrovoltsPerCount: number;
  readonly waveformPretriggerSamples: number;
  readonly waveformPointCount: number;
  inputConfigurationHash(channelCount: number, channelLayoutId: string): string;
  lfpAt(sample: bigint, channel: number): number;
  sampleAt(sample: bigint, channel: number): PreviewNeuralSample;
  eventCountInRange(channel: number, start: bigint, endExclusive: bigint): number;
  eventCentersInRange(
    channel: number,
    start: bigint,
    endExclusive: bigint,
  ): Generator<bigint, void, undefined>;
  waveformAtEvent(channel: number, center: bigint): readonly number[];
}
