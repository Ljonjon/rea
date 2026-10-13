import { expect, it } from "vitest";
import { nativeWindowsUiCapabilities } from "./NativeWindowsUiProviderMetadata.js";
import type { WindowsNativeLoadResult } from "./WindowsNativeLoader.js";
const loaded = (windowCapture?: true): WindowsNativeLoadResult => ({
  available: true,
  authority: {
    call: () => undefined,
    inspection: {
      abiVersion: 1,
      nodeApiVersion: 8,
      architecture: "x64",
      privateDacl: true,
      atomicJobAssignment: true,
      killOnOwnerClose: true,
      filesystem: {
        requestedPath: "C:\\runtime",
        finalPath: "C:\\runtime",
        filesystem: "NTFS",
        volumeSerial: "0".repeat(16),
        fileId: "0".repeat(32),
        size: 0,
        directory: true,
      },
      ...(windowCapture === undefined ? {} : { windowCapture }),
    },
  },
});
it("requires affirmative inspected capture support on the shipped Windows architecture", () => {
  expect(nativeWindowsUiCapabilities("win32", "arm64")[0]).toMatchObject({
    available: false,
    availabilityCode: "unsupported_host",
  });
  expect(
    nativeWindowsUiCapabilities("win32", "x64", () => loaded())[0],
  ).toMatchObject({ available: false });
  expect(
    nativeWindowsUiCapabilities("win32", "x64", () => loaded(true))[0],
  ).toMatchObject({ available: true });
  expect(
    nativeWindowsUiCapabilities("win32", "x64", () => ({
      available: false,
      reason: "artifact unavailable",
    }))[0],
  ).toMatchObject({ available: false, reason: "artifact unavailable" });
});
