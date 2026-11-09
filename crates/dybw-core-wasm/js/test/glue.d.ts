// panic.test.ts imports the glue under a query string, which makes another module, so another instance. Shorthand
// declarations: the test casts what it imports to the glue's own type.
declare module "*/dybw_core_wasm.js?instance=first";
declare module "*/dybw_core_wasm.js?instance=second";
