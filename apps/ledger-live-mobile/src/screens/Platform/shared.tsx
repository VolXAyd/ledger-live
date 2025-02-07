import useEnv from "@ledgerhq/live-common/lib/hooks/useEnv";
import { useRemoteLiveAppContext } from "@ledgerhq/live-common/lib/platform/providers/RemoteLiveAppProvider";
import {
  FilterParams,
  filterPlatformApps,
} from "@ledgerhq/live-common/lib/platform/PlatformAppProvider/helpers";
import { LiveAppManifest } from "@ledgerhq/live-common/lib/platform/providers/types";
import { AppManifest } from "@ledgerhq/live-common/lib/platform/types";
import { useMemo } from "react";

const defaultArray: LiveAppManifest[] = [];

export const useFilteredManifests = (filterParamsOverride?: FilterParams) => {
  const { state } = useRemoteLiveAppContext();
  const manifests = state?.value?.liveAppByIndex || defaultArray;
  const experimental = useEnv("PLATFORM_EXPERIMENTAL_APPS");

  return useMemo(() => {
    const branches = [
      "stable",
      "soon",
      ...(experimental ? ["experimental"] : []),
    ];

    // TODO improve types, mismatch between LiveAppManifest & AppManifest
    return filterPlatformApps(Array.from(manifests.values()) as AppManifest[], {
      version: "0.0.1",
      platform: "mobile",
      branches,
      ...(filterParamsOverride ?? {}),
    });
  }, [manifests, experimental, filterParamsOverride]);
};
