// @opt2-tealbrick/miniapp-sdk/client — React client (SDK-API §14, types/sdk.ts §C). AppShell is @opt2-tealbrick/ui.

export type { PersonPrincipal, SessionInfo, TbProviderProps, UseAgents, UseHolds, UseScopes, UseSession } from "@opt2-tealbrick/spec/sdk";
export { TbError } from "../server/errors.ts";
// v0.1.42 (C369 D4): the shape `callOp("tb.hold_details", { holdId })` returns (spec 0.1.84 `HoldDetails`; local until the spec pin)
export type { HoldDetails, HoldInputState } from "../server/hold-view.ts";
export { callOp, tbFetch } from "./fetch.ts";
export { TbProvider, useAgents, useHolds, useScopes, useSession } from "./react.ts";
