import cache from "memory-cache";

import getServiceWidget from "utils/config/service-helpers";
import { formatApiCall } from "utils/proxy/api-helpers";
import { httpProxy } from "utils/proxy/http";
import widgets from "widgets/widgets";
import createLogger from "utils/logger";

const proxyName = "wgeasyProxyHandler";
const logger = createLogger(proxyName);
const sessionSIDCacheKey = `${proxyName}__sessionSID`;

async function login(widget, service) {
  const url = formatApiCall(widgets[widget.type].api, { ...widget, endpoint: "session" });

  let sid = cache.get(`${sessionSIDCacheKey}.${service}`);

  try {
    // build params for GET /api/session
    let params;
    if (!sid) {
      params = {};
    } else {
      params = {
        Cookie: `connect.sid=${sid}`,
      };
    }

    // GET /api/session to check if we need to login
    const [, , data, responseHeaders] = await httpProxy(url, params);
    const connectSidCookie = responseHeaders["set-cookie"];
    // get sid from set-cookie if exists
    if (connectSidCookie !== undefined) {
      sid = connectSidCookie
        .find((cookie) => cookie.startsWith("connect.sid="))
        .split(";")[0]
        .replace("connect.sid=", "");
    }

    // if not authenticated, do login with password
    // always been authenticated if wg-easy not require password
    const { authenticated } = JSON.parse(data);
    if (!authenticated) {
      // POST /api/session for authentication
      const [status] = await httpProxy(url, {
        method: "POST",
        body: JSON.stringify({ password: widget.password }),
        headers: {
          "Content-Type": "application/json",
          Cookie: `connect.sid=${sid}`,
        },
      });

      // Return 401 if password is incorrect
      if (status !== 200) {
        throw new Error("Failed to authenticate, check your password");
      }
    }

    // cache authenticated sid
    cache.put(`${sessionSIDCacheKey}.${service}`, sid);
    return sid;
  } catch (e) {
    logger.error(`Error logging into wg-easy, error: ${e}`);
    cache.del(`${sessionSIDCacheKey}.${service}`);
    return null;
  }
}

export default async function wgeasyProxyHandler(req, res) {
  const { group, service } = req.query;

  if (group && service) {
    const widget = await getServiceWidget(group, service);

    if (!widgets?.[widget.type]?.api) {
      return res.status(403).json({ error: { message: "Service does not support API calls" } });
    }

    if (widget) {
      let sid = cache.get(`${sessionSIDCacheKey}.${service}`);

      if (!sid) {
        sid = await login(widget, service);
        if (!sid) {
          return res.status(500).json({ error: { message: "Failed to authenticate with Wg-Easy" } });
        }
      }
      const [status, , data] = await httpProxy(
        formatApiCall(widgets[widget.type].api, { ...widget, endpoint: "wireguard/client" }),
        {
          headers: {
            "Content-Type": "application/json",
            Cookie: `connect.sid=${sid}`,
          },
        },
      );

      // evict cache if unauthorized
      if (status !== 200) {
        cache.del(`${sessionSIDCacheKey}.${service}`);
        logger.error(`Unauthorized access to ${service}`);
        return res.status(500).json({ error: { message: "Unauthorized access" } });
      }

      return res.json(JSON.parse(data));
    }
  }

  return res.status(400).json({ error: { message: "Invalid proxy service type" } });
}
