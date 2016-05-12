if (typeof module !== "undefined")
    module.exports = tl_create;

declare module "tl-create" {
    const TrustedList: typeof tl_create;
    export = TrustedList;
} 