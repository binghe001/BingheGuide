//#region node_modules/@vuepress/shared/dist/index.js
/**
* Determine a link has protocol or not
*/
var isLinkWithProtocol = (link) => /^[a-z][a-z0-9+.-]*:/.test(link) || link.startsWith("//");
var markdownLinkRegexp = /.md((\?|#).*)?$/;
/**
* Determine a link is external or not
*/
var isLinkExternal = (link, base = "/") => isLinkWithProtocol(link) || link.startsWith("/") && !link.startsWith(base) && !markdownLinkRegexp.test(link);
/**
* Determine a link is http link or not
*
* - http://github.com
* - https://github.com
* - //github.com
*/
var isLinkHttp = (link) => /^(https?:)?\/\//.test(link);
/**
* Infer route path of the given raw path
*/
var inferRoutePath = (rawPath) => {
	if (!rawPath || rawPath.endsWith("/")) return rawPath;
	let routePath = rawPath.replace(/(^|\/)README.md$/i, "$1index.html");
	if (routePath.endsWith(".md")) routePath = `${routePath.substring(0, routePath.length - 3)}.html`;
	else if (!routePath.endsWith(".html")) routePath = `${routePath}.html`;
	if (routePath.endsWith("/index.html")) routePath = routePath.substring(0, routePath.length - 10);
	return routePath;
};
var FAKE_HOST = "http://.";
/**
* Normalize the given pathname path to the final route path
*/
var normalizeRoutePath = (pathname, current) => {
	if (!pathname.startsWith("/") && current) {
		const loc = current.slice(0, current.lastIndexOf("/"));
		return inferRoutePath(new URL(`${loc}/${pathname}`, FAKE_HOST).pathname);
	}
	return inferRoutePath(pathname);
};
/**
* Resolve the matched locale path of route path
*/
var resolveLocalePath = (locales, routePath) => {
	const localePaths = Object.keys(locales).sort((a, b) => {
		const levelDelta = b.split("/").length - a.split("/").length;
		if (levelDelta !== 0) return levelDelta;
		return b.length - a.length;
	});
	for (const localePath of localePaths) if (routePath.startsWith(localePath)) return localePath;
	return "/";
};
/**
* For a give URL, remove the origin and the site base to get the route path
*/
var resolveRoutePathFromUrl = (url, base = "/") => {
	const pathname = url.replace(/^(?:https?:)?\/\/[^/]*/, "");
	return pathname.startsWith(base) ? `/${pathname.slice(base.length)}` : pathname;
};
var SPLIT_CHAR_REGEXP = /(#|\?)/;
/**
* Split a path into pathname and hashAndQueries
*/
var splitPath = (path) => {
	const [pathname, ...hashAndQueries] = path.split(SPLIT_CHAR_REGEXP);
	return {
		pathname,
		hashAndQueries: hashAndQueries.join("")
	};
};
var TAGS_ALLOWED = [
	"link",
	"meta",
	"script",
	"style",
	"noscript",
	"template"
];
var TAGS_UNIQUE = ["title", "base"];
/**
* Resolve identifier of a tag, to avoid duplicated tags in `<head>`
*/
var resolveHeadIdentifier = ([tag, attrs, content]) => {
	if (TAGS_UNIQUE.includes(tag)) return tag;
	if (!TAGS_ALLOWED.includes(tag)) return null;
	if (tag === "meta" && attrs.name) return `${tag}.${attrs.name}`;
	if (tag === "template" && attrs.id) return `${tag}.${attrs.id}`;
	return JSON.stringify([
		tag,
		Object.entries(attrs).map(([key, value]) => {
			if (typeof value === "boolean") return value ? [key, ""] : null;
			return [key, value];
		}).filter((item) => item != null).sort(([keyA], [keyB]) => keyA.localeCompare(keyB)),
		content
	]);
};
/**
* Dedupe head config with identifier
*
* Items that appear earlier have higher priority
*/
var dedupeHead = (head) => {
	const identifierSet = /* @__PURE__ */ new Set();
	const result = [];
	head.forEach((item) => {
		const identifier = resolveHeadIdentifier(item);
		if (identifier && !identifierSet.has(identifier)) {
			identifierSet.add(identifier);
			result.push(item);
		}
	});
	return result;
};
/**
* Ensure a url string to have leading slash /
*/
var ensureLeadingSlash = (str) => str.startsWith("/") ? str : `/${str}`;
/**
* Ensure a url string to have ending slash /
*/
var ensureEndingSlash = (str) => str.endsWith("/") || str.endsWith(".html") ? str : `${str}/`;
/**
* Format a date string to `yyyy-MM-dd`
*/
var formatDateString = (str, defaultDateString = "") => {
	const dateMatch = str.match(/\b(\d{4})-(\d{1,2})-(\d{1,2})\b/);
	if (dateMatch === null) return defaultDateString;
	const [, yearStr, monthStr, dayStr] = dateMatch;
	return [
		yearStr,
		monthStr.padStart(2, "0"),
		dayStr.padStart(2, "0")
	].join("-");
};
/**
* Omit properties from an object
*/
var omit = (obj, ...keys) => {
	const result = { ...obj };
	for (const key of keys) delete result[key];
	return result;
};
/**
* Remove ending slash / from a string
*/
var removeEndingSlash = (str) => str.endsWith("/") ? str.slice(0, -1) : str;
/**
* Remove leading slash / from a string
*/
var removeLeadingSlash = (str) => str.startsWith("/") ? str.slice(1) : str;
/**
* Check if a value is a function
*/
var isFunction = (val) => typeof val === "function";
/**
* Check if a value is plain object, with generic type support
*/
var isPlainObject = (val) => Object.prototype.toString.call(val) === "[object Object]";
/**
* Check if a value is a string
*/
var isString = (val) => typeof val === "string";
//#endregion
export { dedupeHead, ensureEndingSlash, ensureLeadingSlash, formatDateString, inferRoutePath, isFunction, isLinkExternal, isLinkHttp, isLinkWithProtocol, isPlainObject, isString, normalizeRoutePath, omit, removeEndingSlash, removeLeadingSlash, resolveHeadIdentifier, resolveLocalePath, resolveRoutePathFromUrl, splitPath };

//# sourceMappingURL=@vuepress_shared.js.map