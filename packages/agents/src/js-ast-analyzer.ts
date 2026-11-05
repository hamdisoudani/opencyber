import * as babelParser from '@babel/parser';
import _traverse from '@babel/traverse';
import {
  type HostEntity,
  type HttpMethod,
  HttpMethodSchema,
  normalizeHostname,
  type ObservedEndpointItem,
  type RouteObservationBatch,
  RouteObservationBatchSchema,
  sha256Hex,
} from '@opencyber/shared';
import YAML from 'yaml';

const traverse: typeof _traverse =
  typeof _traverse === 'function'
    ? _traverse
    : (_traverse as unknown as { default: typeof _traverse }).default;

export interface AnalyzeJsBundleOptions {
  code: string;
  targetHost: string;
  runId: string;
  sourceLabel?: string;
}

export interface ExtractOpenApiOptions {
  specContent: string;
  defaultHost: string;
  runId: string;
}

const HTTP_MEMBER_METHODS = new Set<string>([
  'get',
  'post',
  'put',
  'patch',
  'delete',
  'options',
  'head',
]);

const NON_HTTP_RECEIVER_NAMES = new Set<string>([
  'headers',
  'searchparams',
  'urlsearchparams',
  'params',
  'formdata',
  'cookies',
  'localstorage',
  'sessionstorage',
  'map',
  'weakmap',
  'reflect',
  'cache',
  'env',
]);

const STATIC_ASSET_EXT_RE =
  /\.(?:js|mjs|cjs|css|scss|less|png|jpg|jpeg|gif|webp|svg|ico|woff|woff2|ttf|eot|map)$/i;

interface AstNodeLike {
  type: string;
  [key: string]: unknown;
}

interface ExtractedUrlExpr {
  rawUrl: string;
  params: string[];
}

function getPropertyKeyName(prop: AstNodeLike): string | null {
  if (prop.type !== 'ObjectProperty' && prop.type !== 'ObjectMethod') {
    return null;
  }
  const key = prop.key as AstNodeLike | undefined;
  if (!key) {
    return null;
  }
  if (!prop.computed && key.type === 'Identifier' && typeof key.name === 'string') {
    return key.name;
  }
  if (key.type === 'StringLiteral' && typeof key.value === 'string') {
    return key.value;
  }
  return null;
}

function extractParamLabelFromExpr(expr: AstNodeLike): string | null {
  if (expr.type === 'Identifier' && typeof expr.name === 'string') {
    return expr.name;
  }
  if (expr.type === 'MemberExpression' && !expr.computed) {
    const prop = expr.property as AstNodeLike | undefined;
    if (prop?.type === 'Identifier' && typeof prop.name === 'string') {
      return prop.name;
    }
  }
  return null;
}

function extractUrlFromAstNode(
  node: AstNodeLike | undefined,
  constStrings: ReadonlyMap<string, string>,
): ExtractedUrlExpr | null {
  if (!node) {
    return null;
  }

  if (node.type === 'StringLiteral' && typeof node.value === 'string') {
    return { rawUrl: node.value, params: [] };
  }

  if (node.type === 'Identifier' && typeof node.name === 'string') {
    const bound = constStrings.get(node.name);
    if (bound !== undefined) {
      return { rawUrl: bound, params: [] };
    }
    return null;
  }

  if (node.type === 'TemplateLiteral') {
    const quasis = (node.quasis as AstNodeLike[] | undefined) ?? [];
    const expressions = (node.expressions as AstNodeLike[] | undefined) ?? [];
    let built = '';
    const params: string[] = [];

    for (let i = 0; i < quasis.length; i += 1) {
      const quasiVal = (quasis[i]?.value as { cooked?: string; raw?: string } | undefined);
      built += quasiVal?.cooked ?? quasiVal?.raw ?? '';

      if (i < expressions.length) {
        const expr = expressions[i]!;
        if (expr.type === 'StringLiteral' && typeof expr.value === 'string') {
          built += expr.value;
        } else if (
          expr.type === 'Identifier' &&
          typeof expr.name === 'string' &&
          constStrings.has(expr.name)
        ) {
          built += constStrings.get(expr.name)!;
        } else {
          built += ':param';
          const paramLabel = extractParamLabelFromExpr(expr);
          if (paramLabel) {
            params.push(paramLabel);
          }
        }
      }
    }

    return { rawUrl: built, params };
  }

  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const left = extractUrlFromAstNode(node.left as AstNodeLike | undefined, constStrings);
    const right = extractUrlFromAstNode(node.right as AstNodeLike | undefined, constStrings);

    if (left && right) {
      return {
        rawUrl: `${left.rawUrl}${right.rawUrl}`,
        params: [...left.params, ...right.params],
      };
    }
    if (left) {
      const rightParam = extractParamLabelFromExpr(node.right as AstNodeLike);
      return {
        rawUrl: `${left.rawUrl}:param`,
        params: rightParam ? [...left.params, rightParam] : [...left.params],
      };
    }
    if (right && right.rawUrl.startsWith('/')) {
      const leftParam = extractParamLabelFromExpr(node.left as AstNodeLike);
      return {
        rawUrl: `:param${right.rawUrl}`,
        params: leftParam ? [leftParam, ...right.params] : [...right.params],
      };
    }
  }

  if (node.type === 'NewExpression') {
    const callee = node.callee as AstNodeLike | undefined;
    const args = (node.arguments as AstNodeLike[] | undefined) ?? [];
    if (callee?.type === 'Identifier' && (callee.name === 'URL' || callee.name === 'Request')) {
      const first = extractUrlFromAstNode(args[0], constStrings);
      const second = extractUrlFromAstNode(args[1], constStrings);
      if (callee.name === 'URL' && first && second && /^https?:\/\//i.test(second.rawUrl)) {
        const base = second.rawUrl.replace(/\/+$/, '');
        const rel = first.rawUrl.startsWith('/') ? first.rawUrl : `/${first.rawUrl}`;
        return {
          rawUrl: `${base}${rel}`,
          params: [...second.params, ...first.params],
        };
      }
      return first;
    }
  }

  return null;
}

function normalizeCandidateRoute(
  rawUrl: string,
  targetHost: string,
): { host: string; rawPath: string; queryParams: string[] } | null {
  const trimmed = rawUrl.trim();
  if (
    !trimmed ||
    trimmed.startsWith('#') ||
    /^(?:mailto:|javascript:|data:|blob:|tel:|ws:|wss:)/i.test(trimmed)
  ) {
    return null;
  }

  let host = targetHost;
  let pathAndQuery = trimmed;

  if (/^https?:\/\//i.test(trimmed)) {
    try {
      const safeForUrl = trimmed.replace(/:param/g, '__OC_PARAM__');
      const parsed = new URL(safeForUrl);
      host = normalizeHostname(parsed.hostname);
      const restoredPath = (parsed.pathname || '/').replace(/__OC_PARAM__/g, ':param');
      const queryParams = Array.from(parsed.searchParams.keys());
      if (STATIC_ASSET_EXT_RE.test(restoredPath)) {
        return null;
      }
      return {
        host,
        rawPath: restoredPath.replace(/\/+/g, '/'),
        queryParams,
      };
    } catch {
      return null;
    }
  }

  if (!pathAndQuery.startsWith('/') || pathAndQuery.startsWith('//')) {
    return null;
  }

  const withoutHash = pathAndQuery.split('#')[0] ?? '/';
  const qIndex = withoutHash.indexOf('?');
  const rawPathname = (qIndex === -1 ? withoutHash : withoutHash.slice(0, qIndex)) || '/';
  const rawQuery = qIndex === -1 ? '' : withoutHash.slice(qIndex + 1);

  if (STATIC_ASSET_EXT_RE.test(rawPathname)) {
    return null;
  }

  const queryParams: string[] = [];
  if (rawQuery) {
    const sp = new URLSearchParams(rawQuery);
    for (const key of sp.keys()) {
      const cleanKey = key.replace(/^:param$/, '').trim();
      if (cleanKey) {
        queryParams.push(cleanKey);
      }
    }
  }

  return {
    host,
    rawPath: rawPathname.replace(/\/+/g, '/'),
    queryParams,
  };
}

function nodeMentionsAuthHeader(node: AstNodeLike | undefined): boolean {
  if (!node) {
    return false;
  }

  if (node.type === 'StringLiteral' && typeof node.value === 'string') {
    return /\b(?:authorization|bearer|x-api-key|x-auth-token)\b/i.test(node.value);
  }

  if (node.type === 'TemplateLiteral') {
    const quasis = (node.quasis as AstNodeLike[] | undefined) ?? [];
    for (const q of quasis) {
      const val = (q.value as { raw?: string; cooked?: string } | undefined);
      const text = val?.cooked ?? val?.raw ?? '';
      if (/\b(?:authorization|bearer|x-api-key|x-auth-token)\b/i.test(text)) {
        return true;
      }
    }
    const exprs = (node.expressions as AstNodeLike[] | undefined) ?? [];
    return exprs.some((e) => nodeMentionsAuthHeader(e));
  }

  if (node.type === 'Identifier' && typeof node.name === 'string') {
    return /(?:auth|bearer|token|apikey)/i.test(node.name);
  }

  if (node.type === 'ObjectExpression') {
    const props = (node.properties as AstNodeLike[] | undefined) ?? [];
    for (const prop of props) {
      const keyName = getPropertyKeyName(prop);
      if (keyName && /^(?:authorization|x-api-key|x-auth-token)$/i.test(keyName)) {
        return true;
      }
      if (prop.type === 'ObjectProperty' && nodeMentionsAuthHeader(prop.value as AstNodeLike)) {
        // Only treat value identifier auth match when inside headers object; callers pass headers subtree
        if (keyName && /^headers$/i.test(keyName)) {
          return true;
        }
      }
    }
  }

  if (node.type === 'NewExpression') {
    const args = (node.arguments as AstNodeLike[] | undefined) ?? [];
    return args.some((arg) => nodeMentionsAuthHeader(arg));
  }

  return false;
}

function inspectHeadersSubtree(headersNode: AstNodeLike | undefined): boolean {
  if (!headersNode) {
    return false;
  }
  if (headersNode.type === 'ObjectExpression') {
    const props = (headersNode.properties as AstNodeLike[] | undefined) ?? [];
    for (const prop of props) {
      const keyName = getPropertyKeyName(prop);
      if (keyName && /^(?:authorization|x-api-key|x-auth-token)$/i.test(keyName)) {
        return true;
      }
      if (prop.type === 'ObjectProperty') {
        const val = prop.value as AstNodeLike | undefined;
        if (
          (val?.type === 'StringLiteral' || val?.type === 'TemplateLiteral') &&
          nodeMentionsAuthHeader(val)
        ) {
          return true;
        }
      }
    }
    return false;
  }
  return nodeMentionsAuthHeader(headersNode);
}

interface ConfigInspection {
  method?: HttpMethod;
  authRequired?: boolean;
  urlExpr?: ExtractedUrlExpr;
  extraParams: string[];
}

function inspectRequestConfigObject(
  objNode: AstNodeLike | undefined,
  constStrings: ReadonlyMap<string, string>,
): ConfigInspection {
  const result: ConfigInspection = { extraParams: [] };
  if (!objNode || objNode.type !== 'ObjectExpression') {
    return result;
  }

  const props = (objNode.properties as AstNodeLike[] | undefined) ?? [];
  for (const prop of props) {
    if (prop.type !== 'ObjectProperty') {
      continue;
    }
    const keyName = getPropertyKeyName(prop);
    if (!keyName) {
      continue;
    }
    const lowerKey = keyName.toLowerCase();
    const valNode = prop.value as AstNodeLike | undefined;

    if (lowerKey === 'method' && valNode?.type === 'StringLiteral' && typeof valNode.value === 'string') {
      const parsedMethod = HttpMethodSchema.safeParse(valNode.value.trim().toUpperCase());
      if (parsedMethod.success) {
        result.method = parsedMethod.data;
      }
    } else if (lowerKey === 'url' || lowerKey === 'path' || lowerKey === 'endpoint') {
      const extracted = extractUrlFromAstNode(valNode, constStrings);
      if (extracted) {
        result.urlExpr = extracted;
      }
    } else if (lowerKey === 'headers') {
      if (inspectHeadersSubtree(valNode)) {
        result.authRequired = true;
      }
    } else if ((lowerKey === 'params' || lowerKey === 'query') && valNode?.type === 'ObjectExpression') {
      const paramProps = (valNode.properties as AstNodeLike[] | undefined) ?? [];
      for (const pp of paramProps) {
        const pName = getPropertyKeyName(pp);
        if (pName) {
          result.extraParams.push(pName);
        }
      }
    }
  }

  return result;
}

function extractGraphqlOperations(text: string): { isGraphql: boolean; params: string[] } {
  const opMatches = Array.from(
    text.matchAll(/\b(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)/g),
  );
  const varMatches = Array.from(text.matchAll(/\$([A-Za-z_][A-Za-z0-9_]*)/g));

  if (opMatches.length === 0) {
    return { isGraphql: false, params: [] };
  }

  const params = new Set<string>();
  for (const m of opMatches) {
    if (m[1]) {
      params.add(m[1]);
    }
  }
  for (const v of varMatches) {
    if (v[1]) {
      params.add(v[1]);
    }
  }

  return { isGraphql: true, params: Array.from(params) };
}

export function analyzeJavaScriptBundleAst(opts: AnalyzeJsBundleOptions): RouteObservationBatch {
  const normalizedTargetHost = normalizeHostname(opts.targetHost);
  const source = opts.sourceLabel ?? 'static-js-ast';
  const nowIso = new Date().toISOString();

  const ast = babelParser.parse(opts.code, {
    sourceType: 'unambiguous',
    errorRecovery: true,
    plugins: ['typescript', 'jsx'],
  });

  const constStrings = new Map<string, string>();

  // Pass 1: collect top-level / block const string bindings (e.g. const API_BASE = '/v1')
  traverse(ast as unknown as Parameters<typeof traverse>[0], {
    VariableDeclarator(path) {
      const parentKind = (path.parent as { kind?: string } | undefined)?.kind;
      if (parentKind !== 'const') {
        return;
      }
      const id = path.node.id as unknown as AstNodeLike;
      const init = path.node.init as unknown as AstNodeLike | undefined;
      if (id.type === 'Identifier' && typeof id.name === 'string' && init) {
        const extracted = extractUrlFromAstNode(init, constStrings);
        if (extracted && extracted.params.length === 0) {
          constStrings.set(id.name, extracted.rawUrl);
        }
      }
    },
  });

  const dedupedEndpoints = new Map<string, ObservedEndpointItem>();
  const discoveredHostnames = new Set<string>([normalizedTargetHost]);

  const recordEndpoint = (item: {
    host: string;
    method: HttpMethod;
    rawPath: string;
    parameters: string[];
    authRequired?: boolean;
    responseContentType?: string;
  }): void => {
    const key = `${item.host}|${item.method}|${item.rawPath}`;
    discoveredHostnames.add(item.host);

    const existing = dedupedEndpoints.get(key);
    if (!existing) {
      dedupedEndpoints.set(key, {
        host: item.host,
        method: item.method,
        rawPath: item.rawPath,
        source,
        parameters: Array.from(new Set(item.parameters)),
        ...(item.authRequired !== undefined ? { authRequired: item.authRequired } : {}),
        ...(item.responseContentType ? { responseContentType: item.responseContentType } : {}),
      });
      return;
    }

    const mergedParams = Array.from(new Set([...existing.parameters, ...item.parameters]));
    existing.parameters = mergedParams;
    if (item.authRequired === true) {
      existing.authRequired = true;
    }
    if (!existing.responseContentType && item.responseContentType) {
      existing.responseContentType = item.responseContentType;
    }
  };

  // Pass 2: discover fetch, axios/router methods, request({ url }) configs, and GraphQL operations
  traverse(ast as unknown as Parameters<typeof traverse>[0], {
    CallExpression(path) {
      const node = path.node as unknown as AstNodeLike;
      const callee = node.callee as AstNodeLike;
      const args = (node.arguments as AstNodeLike[] | undefined) ?? [];

      // 1. fetch(urlArg, initObj?) or window.fetch / globalThis.fetch
      const isDirectFetch = callee.type === 'Identifier' && callee.name === 'fetch';
      const isGlobalFetch =
        callee.type === 'MemberExpression' &&
        !callee.computed &&
        (callee.property as AstNodeLike | undefined)?.type === 'Identifier' &&
        (callee.property as AstNodeLike | undefined)?.name === 'fetch';

      if (isDirectFetch || isGlobalFetch) {
        const urlExpr = extractUrlFromAstNode(args[0], constStrings);
        const initInspection = inspectRequestConfigObject(args[1], constStrings);
        const effectiveUrl = urlExpr ?? initInspection.urlExpr;
        if (effectiveUrl) {
          const route = normalizeCandidateRoute(effectiveUrl.rawUrl, normalizedTargetHost);
          if (route) {
            recordEndpoint({
              host: route.host,
              method: initInspection.method ?? 'GET',
              rawPath: route.rawPath,
              parameters: [
                ...effectiveUrl.params,
                ...route.queryParams,
                ...initInspection.extraParams,
              ],
              authRequired: initInspection.authRequired,
            });
          }
        }
        return;
      }

      // 2. MemberExpression calls: axios.get('/v1/profile'), api.post('/v1/export'), router.get(...)
      if (callee.type === 'MemberExpression' && !callee.computed) {
        const prop = callee.property as AstNodeLike | undefined;
        const obj = callee.object as AstNodeLike | undefined;
        if (prop?.type === 'Identifier' && typeof prop.name === 'string') {
          const methodLower = prop.name.toLowerCase();
          const objNameLower =
            obj?.type === 'Identifier' && typeof obj.name === 'string'
              ? obj.name.toLowerCase()
              : '';

          if (
            HTTP_MEMBER_METHODS.has(methodLower) &&
            !NON_HTTP_RECEIVER_NAMES.has(objNameLower)
          ) {
            const urlExpr = extractUrlFromAstNode(args[0], constStrings);
            if (urlExpr) {
              const route = normalizeCandidateRoute(urlExpr.rawUrl, normalizedTargetHost);
              if (route) {
                let authRequired: boolean | undefined;
                const extraParams: string[] = [];
                for (const extraArg of args.slice(1)) {
                  const cfg = inspectRequestConfigObject(extraArg, constStrings);
                  if (cfg.authRequired) {
                    authRequired = true;
                  }
                  extraParams.push(...cfg.extraParams);
                }

                recordEndpoint({
                  host: route.host,
                  method: methodLower.toUpperCase() as HttpMethod,
                  rawPath: route.rawPath,
                  parameters: [...urlExpr.params, ...route.queryParams, ...extraParams],
                  authRequired,
                });
                return;
              }
            }
          }
        }
      }

      // 3. Config-based calls: request({ url: '/v1/admin/settings', method: 'GET' }), axios({ url: ... })
      for (const arg of args) {
        if (arg.type === 'ObjectExpression') {
          const cfg = inspectRequestConfigObject(arg, constStrings);
          if (cfg.urlExpr) {
            const route = normalizeCandidateRoute(cfg.urlExpr.rawUrl, normalizedTargetHost);
            if (route) {
              recordEndpoint({
                host: route.host,
                method: cfg.method ?? 'GET',
                rawPath: route.rawPath,
                parameters: [
                  ...cfg.urlExpr.params,
                  ...route.queryParams,
                  ...cfg.extraParams,
                ],
                authRequired: cfg.authRequired,
              });
            }
          }
        }
      }
    },

    // 4a. GraphQL TaggedTemplateExpression: gql`query GetUser { ... }` / graphql`mutation ...`
    TaggedTemplateExpression(path) {
      const node = path.node as unknown as AstNodeLike;
      const tag = node.tag as AstNodeLike | undefined;
      const quasi = node.quasi as AstNodeLike | undefined;

      let isGqlTag = false;
      if (tag?.type === 'Identifier' && typeof tag.name === 'string') {
        isGqlTag = /^(?:gql|graphql)$/i.test(tag.name);
      } else if (tag?.type === 'MemberExpression' && !tag.computed) {
        const prop = tag.property as AstNodeLike | undefined;
        if (prop?.type === 'Identifier' && typeof prop.name === 'string') {
          isGqlTag = /^(?:gql|graphql)$/i.test(prop.name);
        }
      } else if (tag?.type === 'CallExpression') {
        const innerCallee = tag.callee as AstNodeLike | undefined;
        if (innerCallee?.type === 'Identifier' && typeof innerCallee.name === 'string') {
          isGqlTag = /^(?:gql|graphql)$/i.test(innerCallee.name);
        }
      }

      if (!isGqlTag || !quasi || quasi.type !== 'TemplateLiteral') {
        return;
      }

      const quasis = (quasi.quasis as AstNodeLike[] | undefined) ?? [];
      const fullText = quasis
        .map((q) => {
          const val = q.value as { cooked?: string; raw?: string } | undefined;
          return val?.cooked ?? val?.raw ?? '';
        })
        .join(' ');

      const extracted = extractGraphqlOperations(fullText);
      recordEndpoint({
        host: normalizedTargetHost,
        method: 'POST',
        rawPath: '/graphql',
        parameters: extracted.params,
        responseContentType: 'application/json',
      });
    },

    // 4b. GraphQL operation strings: "query GetViewer { ... }" / `mutation UpdateRole($id: ID!) { ... }`
    StringLiteral(path) {
      const val = path.node.value;
      if (!/^\s*(?:query|mutation)\s+[A-Za-z_][A-Za-z0-9_]*[\s\S]*\{/.test(val)) {
        return;
      }
      const extracted = extractGraphqlOperations(val);
      if (extracted.isGraphql) {
        recordEndpoint({
          host: normalizedTargetHost,
          method: 'POST',
          rawPath: '/graphql',
          parameters: extracted.params,
          responseContentType: 'application/json',
        });
      }
    },

    TemplateLiteral(path) {
      if (path.parent.type === 'TaggedTemplateExpression') {
        return;
      }
      const quasis = path.node.quasis;
      const fullText = quasis.map((q) => q.value.cooked ?? q.value.raw).join(' ');
      if (!/^\s*(?:query|mutation)\s+[A-Za-z_][A-Za-z0-9_]*[\s\S]*\{/.test(fullText)) {
        return;
      }
      const extracted = extractGraphqlOperations(fullText);
      if (extracted.isGraphql) {
        recordEndpoint({
          host: normalizedTargetHost,
          method: 'POST',
          rawPath: '/graphql',
          parameters: extracted.params,
          responseContentType: 'application/json',
        });
      }
    },
  });

  const hosts: HostEntity[] = Array.from(discoveredHostnames).map((hostname) => ({
    hostname,
    discoveredAt: nowIso,
    sources: [source],
    securityHeaders: {},
    fingerprints: [],
  }));

  return RouteObservationBatchSchema.parse({
    runId: opts.runId,
    agentRole: 'STATIC_JS_AST',
    createdAt: nowIso,
    bundleSha256: sha256Hex(opts.code),
    hosts,
    endpoints: Array.from(dedupedEndpoints.values()),
  });
}

function isRecord(val: unknown): val is Record<string, unknown> {
  return typeof val === 'object' && val !== null && !Array.isArray(val);
}

function extractOpenApiParamNames(paramsNode: unknown): string[] {
  if (!Array.isArray(paramsNode)) {
    return [];
  }
  const names: string[] = [];
  for (const item of paramsNode) {
    if (isRecord(item) && typeof item.name === 'string' && item.name.trim()) {
      names.push(item.name.trim());
    }
  }
  return names;
}

function resolveSecurityRequirement(
  securityNode: unknown,
  fallbackAuth: boolean | undefined,
): boolean | undefined {
  if (!Array.isArray(securityNode)) {
    return fallbackAuth;
  }
  if (securityNode.length === 0) {
    return false;
  }
  const hasAnonymousOption = securityNode.some(
    (entry) => isRecord(entry) && Object.keys(entry).length === 0,
  );
  const hasRequiredScheme = securityNode.some(
    (entry) => isRecord(entry) && Object.keys(entry).length > 0,
  );
  if (hasRequiredScheme && !hasAnonymousOption) {
    return true;
  }
  if (hasAnonymousOption && !hasRequiredScheme) {
    return false;
  }
  return fallbackAuth;
}

export function extractOpenApiObservations(opts: ExtractOpenApiOptions): RouteObservationBatch {
  const nowIso = new Date().toISOString();
  const fallbackHost = normalizeHostname(opts.defaultHost);

  let parsedDoc: unknown;
  try {
    parsedDoc = JSON.parse(opts.specContent);
  } catch {
    parsedDoc = YAML.parse(opts.specContent);
  }

  if (!isRecord(parsedDoc)) {
    throw new Error('Invalid OpenAPI/Swagger specification: root document must be an object.');
  }

  let resolvedHost = fallbackHost;
  let basePath = '';

  // OpenAPI 3.x servers
  if (Array.isArray(parsedDoc.servers) && parsedDoc.servers.length > 0) {
    const firstServer = parsedDoc.servers[0];
    if (isRecord(firstServer) && typeof firstServer.url === 'string') {
      const rawServerUrl = firstServer.url.trim();
      if (/^https?:\/\//i.test(rawServerUrl)) {
        try {
          const serverUrl = new URL(rawServerUrl);
          resolvedHost = normalizeHostname(serverUrl.hostname);
          basePath = serverUrl.pathname === '/' ? '' : serverUrl.pathname.replace(/\/+$/, '');
        } catch {
          // Keep fallbackHost
        }
      } else if (rawServerUrl.startsWith('/')) {
        basePath = rawServerUrl === '/' ? '' : rawServerUrl.replace(/\/+$/, '');
      }
    }
  } else if (typeof parsedDoc.host === 'string' && parsedDoc.host.trim()) {
    // Swagger 2.0 host + basePath
    resolvedHost = normalizeHostname(parsedDoc.host);
    if (typeof parsedDoc.basePath === 'string' && parsedDoc.basePath.trim()) {
      basePath =
        parsedDoc.basePath.trim() === '/' ? '' : parsedDoc.basePath.trim().replace(/\/+$/, '');
    }
  }

  const globalAuthRequired = resolveSecurityRequirement(parsedDoc.security, undefined);
  const globalProduces = Array.isArray(parsedDoc.produces)
    ? parsedDoc.produces.find((p): p is string => typeof p === 'string')
    : undefined;

  const pathsObj = isRecord(parsedDoc.paths) ? parsedDoc.paths : {};
  const dedupedEndpoints = new Map<string, ObservedEndpointItem>();

  const supportedMethods: readonly HttpMethod[] = [
    'GET',
    'HEAD',
    'OPTIONS',
    'POST',
    'PUT',
    'PATCH',
    'DELETE',
  ];

  for (const [rawRouteTemplate, pathItem] of Object.entries(pathsObj)) {
    if (!isRecord(pathItem)) {
      continue;
    }

    const pathLevelParams = extractOpenApiParamNames(pathItem.parameters);
    const templateBracesParams = Array.from(rawRouteTemplate.matchAll(/\{([^}/]+)\}/g))
      .map((m) => m[1]?.trim())
      .filter((p): p is string => Boolean(p));

    const normalizedTemplate = rawRouteTemplate.startsWith('/')
      ? rawRouteTemplate
      : `/${rawRouteTemplate}`;
    const fullRawPath = `${basePath}${normalizedTemplate}`.replace(/\/+/g, '/') || '/';

    for (const httpMethod of supportedMethods) {
      const opNode = pathItem[httpMethod.toLowerCase()];
      if (!isRecord(opNode)) {
        continue;
      }

      const opParams = extractOpenApiParamNames(opNode.parameters);
      const allParams = Array.from(
        new Set([...templateBracesParams, ...pathLevelParams, ...opParams]),
      );

      const authRequired = resolveSecurityRequirement(opNode.security, globalAuthRequired);

      let responseContentType: string | undefined;
      if (isRecord(opNode.responses)) {
        const okResp =
          opNode.responses['200'] ??
          opNode.responses['201'] ??
          opNode.responses.default;
        if (isRecord(okResp) && isRecord(okResp.content)) {
          const mediaTypes = Object.keys(okResp.content);
          if (mediaTypes.length > 0) {
            responseContentType = mediaTypes[0];
          }
        }
      }
      if (!responseContentType && Array.isArray(opNode.produces)) {
        responseContentType = opNode.produces.find((p): p is string => typeof p === 'string');
      }
      if (!responseContentType && globalProduces) {
        responseContentType = globalProduces;
      }

      const key = `${resolvedHost}|${httpMethod}|${fullRawPath}`;
      dedupedEndpoints.set(key, {
        host: resolvedHost,
        method: httpMethod,
        rawPath: fullRawPath,
        source: 'openapi-spec',
        parameters: allParams,
        ...(authRequired !== undefined ? { authRequired } : {}),
        ...(responseContentType ? { responseContentType } : {}),
      });
    }
  }

  return RouteObservationBatchSchema.parse({
    runId: opts.runId,
    agentRole: 'OPENAPI_PARSER',
    createdAt: nowIso,
    bundleSha256: sha256Hex(opts.specContent),
    hosts: [
      {
        hostname: resolvedHost,
        discoveredAt: nowIso,
        sources: ['openapi-spec'],
        securityHeaders: {},
        fingerprints: [],
      },
    ],
    endpoints: Array.from(dedupedEndpoints.values()),
  });
}
