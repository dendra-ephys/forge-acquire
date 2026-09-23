export type HeadstageProfileId =
  | "rhd2132x1"
  | "rhd2132x2"
  | "rhd2164x1"
  | "rhd2164x2"
  | "rhs2116x1"
  | "rhs2116x2"
  | "rhs2116x2_imu"
  | "rhd2132x1_imu"
  | "rhd2132x1_echem"
  | "rhd2132x1_imu_echem"
  | "rhd2164x1_echem"
  | "rhs2116x1_echem"
  | "rhd2132x1_rhs2116x1"
  | "rhd2164x1_rhs2116x1";

export type HeadstageCatalogStatus =
  | "active_product"
  | "active_option"
  | "decode_only";

export interface HeadstageProfile {
  readonly id: HeadstageProfileId;
  readonly label: string;
  readonly dhlVariant: 1 | 2 | 3 | 4 | 5;
  readonly chipCount: 1 | 2;
  readonly dhlFeatureFlags: 0 | 1 | 2 | 3 | 4 | 5 | 6;
  readonly acquisitionChannelCount: 16 | 32 | 48 | 64 | 80 | 128;
  readonly stimulationChannelCount: 0 | 16 | 32;
  readonly imuCapable: boolean;
  readonly chemCapable: boolean;
  readonly hostStimCapabilityV1: boolean;
  /**
   * Electrical-graph closure only.  It is neither a hardware receipt nor a
   * transport, recording, stimulation, or release authorization.
   */
  readonly graphClosed: boolean;
  /** Catalog status is never a hardware, Run, stimulation, or release receipt. */
  readonly catalogStatus: HeadstageCatalogStatus;
}

export const HEADSTAGE_PROFILES: Readonly<Record<HeadstageProfileId, HeadstageProfile>> = {
  rhd2132x1: {
    id: "rhd2132x1", label: "RHD2132 ×1", dhlVariant: 1, chipCount: 1,
    dhlFeatureFlags: 0, acquisitionChannelCount: 32, stimulationChannelCount: 0,
    imuCapable: false, chemCapable: false, hostStimCapabilityV1: false,
    graphClosed: true,
    catalogStatus: "active_product",
  },
  rhd2132x2: {
    id: "rhd2132x2", label: "RHD2132 ×2", dhlVariant: 1, chipCount: 2,
    dhlFeatureFlags: 0, acquisitionChannelCount: 64, stimulationChannelCount: 0,
    imuCapable: false, chemCapable: false, hostStimCapabilityV1: false,
    // The legacy graph is closed, but this identity is decode-only.
    graphClosed: true,
    catalogStatus: "decode_only",
  },
  rhd2164x1: {
    id: "rhd2164x1", label: "RHD2164 ×1", dhlVariant: 2, chipCount: 1,
    dhlFeatureFlags: 0, acquisitionChannelCount: 64, stimulationChannelCount: 0,
    imuCapable: false, chemCapable: false, hostStimCapabilityV1: false,
    graphClosed: false,
    catalogStatus: "active_product",
  },
  rhd2164x2: {
    id: "rhd2164x2", label: "RHD2164 ×2", dhlVariant: 2, chipCount: 2,
    dhlFeatureFlags: 0, acquisitionChannelCount: 128, stimulationChannelCount: 0,
    imuCapable: false, chemCapable: false, hostStimCapabilityV1: false,
    graphClosed: false,
    catalogStatus: "active_product",
  },
  rhs2116x1: {
    id: "rhs2116x1", label: "RHS2116 ×1", dhlVariant: 3, chipCount: 1,
    dhlFeatureFlags: 4, acquisitionChannelCount: 16, stimulationChannelCount: 16,
    imuCapable: false, chemCapable: false, hostStimCapabilityV1: true,
    graphClosed: true,
    catalogStatus: "active_product",
  },
  rhs2116x2: {
    id: "rhs2116x2", label: "RHS2116 ×2", dhlVariant: 3, chipCount: 2,
    dhlFeatureFlags: 4, acquisitionChannelCount: 32, stimulationChannelCount: 32,
    imuCapable: false, chemCapable: false, hostStimCapabilityV1: false,
    graphClosed: true,
    catalogStatus: "active_product",
  },
  rhs2116x2_imu: {
    id: "rhs2116x2_imu", label: "RHS2116 ×2 + IMU", dhlVariant: 3, chipCount: 2,
    dhlFeatureFlags: 6, acquisitionChannelCount: 32, stimulationChannelCount: 32,
    imuCapable: true, chemCapable: false, hostStimCapabilityV1: false,
    // Source: current generated SKiDL summary; not a hardware-ready receipt.
    graphClosed: true,
    catalogStatus: "active_option",
  },
  rhd2132x1_imu: {
    id: "rhd2132x1_imu", label: "RHD2132 ×1 + IMU", dhlVariant: 1, chipCount: 1,
    dhlFeatureFlags: 2, acquisitionChannelCount: 32, stimulationChannelCount: 0,
    imuCapable: true, chemCapable: false, hostStimCapabilityV1: false,
    // Source: current generated SKiDL summary; not a hardware-ready receipt.
    graphClosed: true,
    catalogStatus: "active_option",
  },
  rhd2132x1_echem: {
    id: "rhd2132x1_echem", label: "RHD2132 ×1 + Echem", dhlVariant: 1,
    chipCount: 1, dhlFeatureFlags: 1, acquisitionChannelCount: 32,
    stimulationChannelCount: 0, imuCapable: false, chemCapable: true,
    hostStimCapabilityV1: false, catalogStatus: "active_product",
    graphClosed: true,
  },
  rhd2132x1_imu_echem: {
    id: "rhd2132x1_imu_echem", label: "RHD2132 ×1 + IMU + Echem", dhlVariant: 1,
    chipCount: 1, dhlFeatureFlags: 3, acquisitionChannelCount: 32,
    stimulationChannelCount: 0, imuCapable: true, chemCapable: true,
    hostStimCapabilityV1: false,
    // Source: current generated SKiDL summary; not a hardware-ready receipt.
    graphClosed: true,
    catalogStatus: "active_option",
  },
  rhd2164x1_echem: {
    id: "rhd2164x1_echem", label: "RHD2164 ×1 + Echem", dhlVariant: 2,
    chipCount: 1, dhlFeatureFlags: 1, acquisitionChannelCount: 64,
    stimulationChannelCount: 0, imuCapable: false, chemCapable: true,
    hostStimCapabilityV1: false, catalogStatus: "active_product",
    graphClosed: false,
  },
  rhs2116x1_echem: {
    id: "rhs2116x1_echem", label: "RHS2116 ×1 + Echem", dhlVariant: 3,
    chipCount: 1, dhlFeatureFlags: 5, acquisitionChannelCount: 16,
    stimulationChannelCount: 16, imuCapable: false, chemCapable: true,
    hostStimCapabilityV1: false, catalogStatus: "active_product",
    graphClosed: true,
  },
  rhd2132x1_rhs2116x1: {
    id: "rhd2132x1_rhs2116x1", label: "RHD2132 ×1 + RHS2116 ×1",
    dhlVariant: 4, chipCount: 2, dhlFeatureFlags: 4,
    acquisitionChannelCount: 48, stimulationChannelCount: 16,
    imuCapable: false, chemCapable: false, hostStimCapabilityV1: false,
    graphClosed: false,
    catalogStatus: "active_product",
  },
  rhd2164x1_rhs2116x1: {
    id: "rhd2164x1_rhs2116x1", label: "RHD2164 ×1 + RHS2116 ×1",
    dhlVariant: 5, chipCount: 2, dhlFeatureFlags: 4,
    acquisitionChannelCount: 80, stimulationChannelCount: 16,
    imuCapable: false, chemCapable: false, hostStimCapabilityV1: false,
    graphClosed: false,
    catalogStatus: "active_product",
  },
};

// The simulator models a new synthetic Run, so its default must satisfy the
// same catalog-plus-graph selection gate. This is not a hardware admission.
export const DEFAULT_SYNTHETIC_HEADSTAGE_PROFILE: HeadstageProfileId = "rhd2132x1";

export const RECEIVER_POD_REV_A_CONTRACT = {
  fpga: "LFE5UM-25F-8MG285I",
  usbBridge: "FT600Q-B-T",
  fifoMode: "245 synchronous",
  fifoWidthBits: 16,
  byteEnableBits: 2,
  vccioMillivolts: 2_500,
  fifoClockProfilesHz: { bringup: 66_666_667, release: 100_000_000 },
  cabline: {
    dataDirection: "headstage_to_pod",
    dataLineRateBitsPerSecond: 1_250_000_000,
    dataEncoding: "8b10b",
    controlDirection: "pod_to_headstage",
    controlChipRateBaud: 20_000_000,
    sourceTimebaseHz: 25_000_000,
  },
} as const;

export function headstageProfile(id: HeadstageProfileId): HeadstageProfile {
  return HEADSTAGE_PROFILES[id];
}

/**
 * Catalog + electrical-graph selection only; daemon receipts still own every
 * real Run admission.
 */
export function isNewRunCatalogEligible(id: HeadstageProfileId): boolean {
  const profile = headstageProfile(id);
  return profile.catalogStatus !== "decode_only" && profile.graphClosed;
}
