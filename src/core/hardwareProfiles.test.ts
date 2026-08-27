import { describe, expect, it } from "vitest";
import inventoryContract from "../../../headstage/firmware/component_inventory_profiles.json";
import productMatrix from "../../../headstage/docs/headstage_product_matrix_v1.json";
import {
  HEADSTAGE_PROFILES,
  RECEIVER_POD_REV_A_CONTRACT,
  headstageProfile,
  isNewRunCatalogEligible,
} from "./hardwareProfiles";

const ACTIVE_OPTION_GRAPH_CLOSED_FROM_GENERATED_SKIDL_SUMMARIES = {
  rhd2132x1_imu: true,
  rhd2132x1_imu_echem: true,
  rhs2116x2_imu: true,
} as const;

describe("active Receiver Pod and Headstage contracts", () => {
  it("models the FT601 32-bit CABLINE Rev A Pod without legacy FT600 values", () => {
    expect(RECEIVER_POD_REV_A_CONTRACT.usbBridge).toBe("FT601Q-B-T");
    expect(RECEIVER_POD_REV_A_CONTRACT.fifoWidthBits).toBe(32);
    expect(RECEIVER_POD_REV_A_CONTRACT.byteEnableBits).toBe(4);
    expect(RECEIVER_POD_REV_A_CONTRACT.vccioMillivolts).toBe(2_500);
    expect(RECEIVER_POD_REV_A_CONTRACT.fifoClockProfilesHz).toEqual({
      bringup: 66_666_667,
      release: 100_000_000,
    });
    expect(RECEIVER_POD_REV_A_CONTRACT.cabline.sourceTimebaseHz).toBe(25_000_000);
  });

  it("models ten active products, three active options, and one decode-only profile", () => {
    expect(Object.keys(HEADSTAGE_PROFILES)).toEqual([
      "rhd2132x1", "rhd2132x2", "rhd2164x1", "rhd2164x2",
      "rhs2116x1", "rhs2116x2", "rhs2116x2_imu", "rhd2132x1_imu", "rhd2132x1_echem",
      "rhd2132x1_imu_echem", "rhd2164x1_echem", "rhs2116x1_echem",
      "rhd2132x1_rhs2116x1", "rhd2164x1_rhs2116x1",
    ]);
    expect(
      Object.values(HEADSTAGE_PROFILES)
        .filter((profile) => profile.catalogStatus === "decode_only")
        .map((profile) => [profile.id, profile.catalogStatus]),
    ).toEqual([
      ["rhd2132x2", "decode_only"],
    ]);
    expect(
      Object.values(HEADSTAGE_PROFILES)
        .filter((profile) => profile.catalogStatus === "active_option")
        .map((profile) => profile.id),
    ).toEqual(["rhs2116x2_imu", "rhd2132x1_imu", "rhd2132x1_imu_echem"]);
    expect(
      Object.values(HEADSTAGE_PROFILES)
        .filter((profile) => profile.catalogStatus === "active_product")
        .map((profile) => profile.id).sort(),
    ).toEqual(productMatrix.products.map((product) => product.name).sort());
    expect(productMatrix.decode_only_profiles).toEqual(["rhd2132x2"]);
    for (const product of productMatrix.products) {
      const profile = headstageProfile(product.name as keyof typeof HEADSTAGE_PROFILES);
      expect(profile.graphClosed, product.name).toBe(product.graph_closed);
    }
    for (const [id, graphClosed] of Object.entries(
      ACTIVE_OPTION_GRAPH_CLOSED_FROM_GENERATED_SKIDL_SUMMARIES,
    )) {
      expect(headstageProfile(id as keyof typeof HEADSTAGE_PROFILES).graphClosed, id)
        .toBe(graphClosed);
    }
    expect(headstageProfile("rhd2132x2").graphClosed).toBe(true);
    expect(isNewRunCatalogEligible("rhd2132x2")).toBe(false);
    expect(isNewRunCatalogEligible("rhd2132x1_rhs2116x1")).toBe(false);
    expect(
      Object.values(HEADSTAGE_PROFILES)
        .filter((profile) => isNewRunCatalogEligible(profile.id))
        .map((profile) => profile.id)
        .sort(),
    ).toEqual([
      "rhd2132x1", "rhd2132x1_echem", "rhd2132x1_imu",
      "rhd2132x1_imu_echem", "rhs2116x1", "rhs2116x1_echem", "rhs2116x2",
      "rhs2116x2_imu",
    ]);
    expect(
      Object.values(HEADSTAGE_PROFILES).map((profile) => [
        profile.dhlVariant,
        profile.chipCount,
        profile.dhlFeatureFlags,
        profile.acquisitionChannelCount,
      ]),
    ).toEqual([
      [1, 1, 0, 32], [1, 2, 0, 64], [2, 1, 0, 64],
      [2, 2, 0, 128], [3, 1, 4, 16], [3, 2, 4, 32], [3, 2, 6, 32],
      [1, 1, 2, 32], [1, 1, 1, 32], [1, 1, 3, 32],
      [2, 1, 1, 64], [3, 1, 5, 16], [4, 2, 4, 48], [5, 2, 4, 80],
    ]);
  });

  it("matches the checked-in firmware inventory assemblies instead of a copied profile count", () => {
    const firmwareProfiles = new Map(
      inventoryContract.profiles.map((profile) => [profile.id, profile]),
    );
    expect(inventoryContract.assemblies.map((assembly) => assembly.name).sort()).toEqual(
      Object.keys(HEADSTAGE_PROFILES).sort(),
    );
    for (const assembly of inventoryContract.assemblies) {
      const firmware = firmwareProfiles.get(assembly.board_profile_id);
      const host = HEADSTAGE_PROFILES[assembly.name as keyof typeof HEADSTAGE_PROFILES];
      expect(firmware).toBeDefined();
      expect(host).toBeDefined();
      expect([
        host.dhlVariant,
        host.chipCount,
        host.dhlFeatureFlags,
        host.acquisitionChannelCount,
      ]).toEqual([
        firmware?.variant,
        firmware?.components.length,
        assembly.descriptor_feature_flags,
        firmware?.components.reduce((total, component) => total + component.channel_count, 0),
      ]);
    }
  });

  it("exposes optional sensor capabilities without granting stimulation authority", () => {
    const imu = headstageProfile("rhd2132x1_imu");
    const echem = headstageProfile("rhd2132x1_imu_echem");
    const rhsImu = headstageProfile("rhs2116x2_imu");
    const mixed = headstageProfile("rhd2132x1_rhs2116x1");

    expect(imu).toMatchObject({
      imuCapable: true,
      chemCapable: false,
      stimulationChannelCount: 0,
      hostStimCapabilityV1: false,
    });
    expect(echem).toMatchObject({
      imuCapable: true,
      chemCapable: true,
      stimulationChannelCount: 0,
      hostStimCapabilityV1: false,
    });
    expect(mixed).toMatchObject({
      catalogStatus: "active_product",
      stimulationChannelCount: 16,
      hostStimCapabilityV1: false,
    });
    expect(rhsImu).toMatchObject({
      catalogStatus: "active_option",
      graphClosed: true,
      imuCapable: true,
      stimulationChannelCount: 32,
      hostStimCapabilityV1: false,
    });
    expect(
      Object.values(HEADSTAGE_PROFILES).filter((profile) => profile.hostStimCapabilityV1)
        .map((profile) => profile.id),
    ).toEqual(["rhs2116x1"]);
  });

  it("does not misrepresent RHS2116 x2 as the 16-channel M0 stimulation capability", () => {
    expect(headstageProfile("rhs2116x1").hostStimCapabilityV1).toBe(true);
    expect(headstageProfile("rhs2116x2").stimulationChannelCount).toBe(32);
    expect(headstageProfile("rhs2116x2").hostStimCapabilityV1).toBe(false);
    expect(headstageProfile("rhs2116x2_imu").stimulationChannelCount).toBe(32);
    expect(headstageProfile("rhs2116x2_imu").hostStimCapabilityV1).toBe(false);
  });
});
