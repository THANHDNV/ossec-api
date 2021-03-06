var router = require('express').Router();

/**
 * @api {get} /agents Get all agents
 * @apiName GetAgents
 * @apiGroup Info
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [select] List of selected fields.
 * @apiParam {String="active", "pending", "neverconnected", "disconnected"} [status] Filters by agent status. Use commas to enter multiple statuses.
 * @apiParam {String} [older_than] Filters out disconnected agents for longer than specified. Time in seconds, '[n_days]d', '[n_hours]h', '[n_minutes]m' or '[n_seconds]s'. For never connected agents, uses the register date.
 * @apiParam {String} [os.platform] Filters by OS platform.
 * @apiParam {String} [os.version] Filters by OS version.
 * @apiParam {String} [manager] Filters by manager hostname to which agents are connected.
 * @apiParam {String} [version] Filters by agents version.
 * @apiParam {String} [group] Filters by group of agents.
 * @apiParam {String} [node] Filters by node name.
 *
 * @apiDescription Returns a list with the available agents.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/agents?pretty&offset=0&limit=5&sort=-ip,name"
 *
 */
router.get('/', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /agents");

    req.apicacheGroup = "agents";

    var data_request = {'function': '/agents', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param',
                   'select':'select_param', 'search':'search_param',
                    'status':'alphanumeric_param', 'os.platform':'alphanumeric_param',
                   'os.version':'alphanumeric_param', 'manager':'alphanumeric_param',
                   'version':'alphanumeric_param', 'node': 'alphanumeric_param',
                    'older_than':'timeframe_type', 'group':'alphanumeric_param',
                    'name': 'alphanumeric_param', 'ip': 'ips'};

    if (!filter.check(req.query, filters, req, res))  // Filter with error
        return;

    data_request['arguments']['filters'] = {}

    if ('offset' in req.query)
        data_request['arguments']['offset'] = Number(req.query.offset);
    if ('limit' in req.query)
        data_request['arguments']['limit'] = Number(req.query.limit);
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);
    if ('select' in req.query)
        data_request['arguments']['select'] = filter.select_param_to_json(req.query.select);
    if ('status' in req.query)
        data_request['arguments']['filters']['status'] = req.query.status;
    if ('os.platform' in req.query)
        data_request['arguments']['filters']['os_platform'] = req.query['os.platform'];
    if ('os.version' in req.query)
        data_request['arguments']['filters']['os_version'] = req.query['os.version'];
    if ('manager' in req.query)
        data_request['arguments']['filters']['manager_host'] = req.query['manager'];
    if ('node' in req.query)
        data_request['arguments']['filters']['node_name'] = req.query['node'];
    if ('version' in req.query)
        data_request['arguments']['filters']['version'] = req.query['version'];
    if ('older_than' in req.query)
        data_request['arguments']['filters']['older_than'] = req.query['older_than'];
    if ('group' in req.query)
        data_request['arguments']['filters']['group'] = req.query['group'];
    if ('ip' in req.query)
        data_request['arguments']['filters']['ip'] = req.query.ip;
    if ('name' in req.query)
        data_request['arguments']['filters']['name'] = req.query.name;

    execute.exec(python_bin, [ossec_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /agents/summary Get agents summary
 * @apiName GetAgentsSummary
 * @apiGroup Info
 *
 *
 * @apiDescription Returns a summary of the available agents.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/agents/summary?pretty"
 *
 */
router.get('/summary', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /agents/summary");

    req.apicacheGroup = "agents";

    var data_request = {'function': '/agents/summary', 'arguments': {}};
    execute.exec(python_bin, [ossec_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /agents/outdated Get outdated agents
 * @apiName GetOutdatedAgents
 * @apiGroup Upgrade
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 *
 * @apiDescription Returns the list of outdated agents.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/agents/outdated?pretty"
 *
 */
router.get('/outdated', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /agents/outdated");

    req.apicacheGroup = "agents";

    var data_request = {'function': '/agents/outdated', 'arguments': {}};
    var filters = {'offset': 'numbers', 'limit': 'numbers', 'sort':'sort_param'};

    if (!filter.check(req.query, filters, req, res))  // Filter with error
        return;

    if ('offset' in req.query)
        data_request['arguments']['offset'] = Number(req.query.offset);
    if ('limit' in req.query)
        data_request['arguments']['limit'] = Number(req.query.limit);
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);

    execute.exec(python_bin, [ossec_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {get} /agents/name/:agent_name Get an agent by its name
 * @apiName GetAgentsName
 * @apiGroup Info
 *
 * @apiParam {String} agent_name Agent name.
 * @apiParam {String} [select] List of selected fields.
 *
 * @apiDescription Returns various information from an agent called :agent_name.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/agents/name/NewHost?pretty"
 *
 */
router.get('/name/:agent_name', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /agents/name/:agent_name");

    req.apicacheGroup = "agents";

    var data_request = {'function': '/agents/name/:agent_name', 'arguments': {}};
    var filters = {'select':'select_param'};

    if (!filter.check(req.params, {'agent_name':'names'}, req, res))  // Filter with error
        return;

    data_request['arguments']['agent_name'] = req.params.agent_name;

    if(!filter.check(req.query, filters, req, res)) // Filter with error
        return;

    if ('select' in req.query)
        data_request['arguments']['select'] =
        filter.select_param_to_json(req.query.select);

    execute.exec(python_bin, [ossec_control], data_request, function (data) { res_h.send(req, res, data); });

})

/**
 * @api {get} /agents/:agent_id Get an agent
 * @apiName GetAgentsID
 * @apiGroup Info
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {String} [select] List of selected fields.
 *
 * @apiDescription Returns various information from an agent.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/agents/000?pretty"
 *
 */
router.get('/:agent_id', cache(), function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /agents/:agent_id");

    req.apicacheGroup = "agents";

    var data_request = {'function': '/agents/:agent_id', 'arguments': {}};
    var filters = {'select':'select_param'};

    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))  // Filter with error
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;

    if(!filter.check(req.query, filters, req, res)) // Filter with error
        return;

    if ('select' in req.query)
        data_request['arguments']['select'] =
        filter.select_param_to_json(req.query.select);

    execute.exec(python_bin, [ossec_control], data_request, function (data) { res_h.send(req, res, data); });

})

/**
 * @api {get} /agents/:agent_id/key Get agent key
 * @apiName GetAgentsKey
 * @apiGroup Key
 *
 * @apiParam {Number} agent_id Agent ID.
 *
 * @apiDescription Returns the key of an agent.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/agents/004/key?pretty"
 *
 */
router.get('/:agent_id/key', function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /agents/:agent_id/key");

    var data_request = {'function': '/agents/:agent_id/key', 'arguments': {}};

    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))  // Filter with error
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(python_bin, [ossec_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {get} /agents/:agent_id/upgrade_result Get upgrade result from agent
 * @apiName GetUpgradeResult
 * @apiGroup Upgrade
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {Number} [timeout=3] Seconds to wait for the agent to respond.
 *
 * @apiDescription Returns the upgrade result from an agent.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/agents/003/upgrade_result?pretty"
 *
 */
router.get('/:agent_id/upgrade_result', function(req, res) {
    logger.debug(req.connection.remoteAddress + " GET /agents/:agent_id/upgrade_result");

    var data_request = {'function': '/agents/:agent_id/upgrade_result', 'arguments': {}};

    if (!filter.check(req.query, {'timeout':'numbers'}, req, res))  // Filter with error
        return;

    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))  // Filter with error
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;
    if ('timeout' in req.query)
        data_request['arguments']['timeout'] = req.query.timeout;

    execute.exec(python_bin, [ossec_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {put} /agents/restart Restart all agents
 * @apiName PutAgentsRestart
 * @apiGroup Restart
 *
 * @apiDescription Restarts all agents.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X PUT "https://127.0.0.1:55000/agents/restart?pretty"
 *
 */
router.put('/restart', function(req, res) {
    logger.debug(req.connection.remoteAddress + " PUT /agents/restart");

    var data_request = {'function': 'PUT/agents/restart', 'arguments': {}};

    data_request['arguments']['restart_all'] = 'True';

    execute.exec(python_bin, [ossec_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {post} /agents/restart Restart a list of agents
 * @apiName PostAgentListRestart
 * @apiGroup Restart
 *
 * @apiParam {String[]} ids Array of agent ID's.
 *
 * @apiDescription Restarts a list of agents.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X POST -H "Content-Type:application/json" -d '{"ids":["002","004"]}' "https://127.0.0.1:55000/agents/restart?pretty"
 *
 */
router.post('/restart', function(req, res) {
    logger.debug(req.connection.remoteAddress + " POST /agents/restart");

    var data_request = {'function': 'POST/agents/restart', 'arguments': {}};

    if (!filter.check(req.body, {'ids':'array_numbers'}, req, res))  // Filter with error
        return;

    data_request['arguments']['agent_id'] = req.body.ids;

    if ('ids' in req.body){
        data_request['arguments']['agent_id'] = req.body.ids;
        execute.exec(python_bin, [ossec_control], data_request, function (data) { res_h.send(req, res, data); });
    }else
        res_h.bad_request(req, res, 604, "Missing field: 'ids'");
})

/**
 * @api {put} /agents/:agent_id/restart Restart an agent
 * @apiName PutAgentsRestartId
 * @apiGroup Restart
 *
 * @apiParam {Number} agent_id Agent unique ID.
 *
 * @apiDescription Restarts the specified agent.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X PUT "https://127.0.0.1:55000/agents/007/restart?pretty"
 *
 */
router.put('/:agent_id/restart', function(req, res) {
    logger.debug(req.connection.remoteAddress + " PUT /agents/:agent_id/restart");

    var data_request = {'function': 'PUT/agents/:agent_id/restart', 'arguments': {}};

    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))  // Filter with error
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;

    execute.exec(python_bin, [ossec_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {put} /agents/:agent_id/upgrade Upgrade agent using online repository
 * @apiName PutAgentsUpgradeId
 * @apiGroup Upgrade
 *
 * @apiParam {Number} agent_id Agent unique ID.
 * @apiParam {String} [wpk_repo] WPK repository.
 * @apiParam {String} [version] Wazuh version.
 * @apiParam {Boolean} [use_http] Use protocol http. If it's false use https. By default the value is set to false.
 * @apiParam {number="0","1"} [force] Force upgrade.
 *
 * @apiDescription Upgrade the agent using a WPK file from online repository.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X PUT "https://127.0.0.1:55000/agents/002/upgrade?pretty"
 *
 */
router.put('/:agent_id/upgrade', function(req, res) {
    logger.debug(req.connection.remoteAddress + " PUT /agents/:agent_id/upgrade");

    var data_request = {'function': 'PUT/agents/:agent_id/upgrade', 'arguments': {}};
    var filters = { 'wpk_repo': 'paths', 'version': 'alphanumeric_param', 'force': 'numbers', 'use_http': 'boolean'};

    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))
        return;

    if (!filter.check(req.query, filters, req, res))
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;
    if ('wpk_repo' in req.query)
        data_request['arguments']['wpk_repo'] = req.query.wpk_repo;
    if ('version' in req.query)
        data_request['arguments']['version'] = req.query.version;
    if ('force' in req.query)
        data_request['arguments']['force'] = req.query.force;
    if ('use_http' in req.query)
        data_request['arguments']['use_http'] = (req.query.use_http == true || req.query.use_http == 'true');

    execute.exec(python_bin, [ossec_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {put} /agents/:agent_id/upgrade_custom Upgrade agent using custom file
 * @apiName PutAgentsUpgradeCustomId
 * @apiGroup Upgrade
 *
 * @apiParam {Number} agent_id Agent unique ID.
 * @apiParam {String} file_path WPK file path.
 * @apiParam {String} installer Installation script.
 *
 * @apiDescription Upgrade the agent using a custom file.
 *
 * @apiExample {curl} Example usage*:
 *     curl -u foo:bar -k -X PUT "https://127.0.0.1:55000/agents/002/upgrade_custom?pretty"
 *
 */
router.put('/:agent_id/upgrade_custom', function(req, res) {
    logger.debug(req.connection.remoteAddress + " PUT /agents/:agent_id/upgrade_custom");

    var data_request = {'function': 'PUT/agents/:agent_id/upgrade_custom', 'arguments': {}};
    var filters = {'file_path':'paths', 'installer':'alphanumeric_param'};

    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))
        return;

    if (!filter.check(req.query, filters, req, res))
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;
    if ('file_path' in req.query)
        data_request['arguments']['file_path'] = req.query.file_path;
    if ('installer' in req.query)
        data_request['arguments']['installer'] = req.query.installer;

    execute.exec(python_bin, [ossec_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {put} /agents/:agent_name Add agent (quick method)
 * @apiName PutAddAgentName
 * @apiGroup Add
 *
 * @apiParam {String} agent_name Agent name.
 *
 * @apiDescription Adds a new agent with name :agent_name. This agent will use ANY as IP.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X PUT "https://127.0.0.1:55000/agents/myNewAgent?pretty"
 *
 */
router.put('/:agent_name', function(req, res) {
    logger.debug(req.connection.remoteAddress + " PUT /agents/:agent_name");

    var data_request = {'function': 'PUT/agents/:agent_name', 'arguments': {}};

    if (!filter.check(req.params, {'agent_name':'names'}, req, res))  // Filter with error
        return;

    data_request['arguments']['name'] = req.params.agent_name;

    execute.exec(python_bin, [ossec_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {delete} /agents/:agent_id Delete an agent
 * @apiName DeleteAgentId
 * @apiGroup Delete
 *
 * @apiParam {Number} agent_id Agent ID.
 * @apiParam {String} purge Delete an agent from the key store.
 *
 * @apiDescription Removes an agent.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X DELETE "https://127.0.0.1:55000/agents/008?pretty"
 *
 */
router.delete('/:agent_id', function(req, res) {
    logger.debug(req.connection.remoteAddress + " DELETE /agents/:agent_id");

    var data_request = {'function': 'DELETE/agents/:agent_id', 'arguments': {}};

    if (!filter.check(req.params, {'agent_id':'numbers'}, req, res))  // Filter with error
        return;

    data_request['arguments']['agent_id'] = req.params.agent_id;
    data_request['arguments']['purge'] = 'purge' in req.query ? true : false;

    execute.exec(python_bin, [ossec_control], data_request, function (data) { res_h.send(req, res, data); });
})

/**
 * @api {delete} /agents Delete agents
 * @apiName DeleteAgents
 * @apiGroup Delete
 *
 * @apiParam {String[]} ids Array of agent ID's.
 * @apiParam {Boolean} purge Delete an agent from the key store.
 * @apiParam {String="active", "pending", "neverconnected", "disconnected"} [status] Filters by agent status. Use commas to enter multiple statuses.
 * @apiParam {String} older_than Filters out disconnected agents for longer than specified. Time in seconds, '[n_days]d', '[n_hours]h', '[n_minutes]m' or '[n_seconds]s'. For never connected agents, uses the register date.
 *
 * @apiDescription Removes agents, using a list of them or a criterion based on the status or time of the last connection. The Wazuh API must be restarted after removing an agent.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X DELETE -H "Content-Type:application/json" -d '{"ids":["003","005"]}' "https://127.0.0.1:55000/agents?pretty&older_than=10s"
 *
 */
router.delete('/', function(req, res) {
    logger.debug(req.connection.remoteAddress + " DELETE /agents");

    var data_request = { 'function': 'DELETE/agents/', 'arguments': {}};
    var filter_body = { 'ids': 'array_numbers', 'purge': 'boolean'};
    var filter_query = { 'older_than': 'timeframe_type', 'status': 'alphanumeric_param', 'purge': 'empty_boolean' };

    if (!filter.check(req.body, filter_body, req, res))  // Filter with error
        return;

    if (!filter.check(req.query, filter_query, req, res))  // Filter with error
        return;

    if (!('ids' in req.body) && !('status' in req.query)){
        res_h.bad_request(req, res, 604, "Missing field: You have to specified 'ids' or status.");
        return;
    }

    if ('purge' in req.body && 'purge' in req.query) // the most restrictive wins
        data_request['arguments']['purge'] = (req.query.purge == 'true' || req.query.purge == '') && (req.body.purge == 'true' || req.body.purge == true);
    else if ('purge' in req.body)
        data_request['arguments']['purge'] = (req.body.purge == 'true' || req.body.purge == true);
    else if ('purge' in req.query)
        data_request['arguments']['purge'] = (req.query.purge == 'true' || req.query.purge == '');

    if ('ids' in req.body)
        data_request['arguments']['list_agent_ids'] = req.body.ids;

    if ('older_than' in req.query)
        data_request['arguments']['older_than'] = req.query.older_than;

    if ('status' in req.query)
        data_request['arguments']['status'] = req.query.status;

    execute.exec(python_bin, [ossec_control], data_request, function (data) { res_h.send(req, res, data); });
})


/**
 * @api {post} /agents Add agent
 * @apiName PostAddAgentId
 * @apiGroup Add
 *
 * @apiParam {String} name Agent name.
 * @apiParam {String="IP","IP/NET", "ANY"} [ip] If this is not included, the API will get the IP automatically. If you are behind a proxy, you must set the option config.BehindProxyServer to yes at config.js.
 * @apiParam {Number} [force] Remove the old agent with the same IP if disconnected since <force> seconds.
 *
 * @apiDescription Add a new agent.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X POST -d '{"name":"NewHost","ip":"10.0.0.9"}' -H 'Content-Type:application/json' "https://127.0.0.1:55000/agents?pretty"
 *
 */
router.post('/', function(req, res) {
    logger.debug(req.connection.remoteAddress + " POST /agents");

    // If not IP set, we will use source IP.
    var ip = req.body.ip;
    if ( !ip ){
        // If we hare behind a proxy server, use headers.
        if (config.BehindProxyServer.toLowerCase() == "yes")
            if (!req.headers.hasOwnProperty('x-forwarded-for')){
                res_h.bad_request(req, res, 800);
                return;
            }
            else
                ip = req.headers['x-forwarded-for'];
        else
            ip = req.connection.remoteAddress;

        // Extract IPv4 from IPv6 hybrid notation
        if (ip.indexOf("::ffff:") > -1) {
            var ipFiltered = ip.split(":");
            ip = ipFiltered[ipFiltered.length-1];
            logger.debug("Hybrid IPv6 IP filtered: " + ip);
        }
        logger.debug("Add agent with automatic IP: " + ip);
    }
    req.body.ip = ip;

    var data_request = {'function': 'POST/agents', 'arguments': {}};
    var filters = {'name':'names', 'ip':'ips', 'force':'numbers'};

    if (!filter.check(req.body, filters, req, res))  // Filter with error
        return;

    data_request['arguments']['ip'] = req.body.ip;

    if ('name' in req.body){
        data_request['arguments']['name'] = req.body.name;
        if ('force' in req.body){
            data_request['arguments']['force'] = req.body.force;
        }
        execute.exec(python_bin, [ossec_control], data_request, function (data) { res_h.send(req, res, data); });
    }else
        res_h.bad_request(req, res, 604, "Missing field: 'name'");
})


/**
 * @api {post} /agents/insert Insert agent
 * @apiName PostInsertAgent
 * @apiGroup Add
 *
 * @apiParam {String} name Agent name.
 * @apiParam {String="IP","IP/NET", "ANY"} [ip] If this is not included, the API will get the IP automatically. If you are behind a proxy, you must set the option config.BehindProxyServer to yes at config.js.
 * @apiParam {String} id Agent ID.
 * @apiParam {String} key Agent key. Minimum length: 64 characters. Allowed values: ^[a-zA-Z0-9]+$
 * @apiParam {Number} [force] Remove the old agent the with same IP if disconnected since <force> seconds.
 *
 * @apiDescription Insert an agent with an existing id and key.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X POST -d '{"name":"NewHost_2","ip":"10.0.10.10","id":"123","key":"1abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghi64"}' -H 'Content-Type:application/json' "https://127.0.0.1:55000/agents/insert?pretty"
 *
 */
router.post('/insert', function(req, res) {
    logger.debug(req.connection.remoteAddress + " POST /agents/insert");

    // If not IP set, we will use source IP.
    var ip = req.body.ip;
    if ( !ip ){
        // If we hare behind a proxy server, use headers.
        if (config.BehindProxyServer.toLowerCase() == "yes")
            if (!req.headers.hasOwnProperty('x-forwarded-for')){
                res_h.bad_request(req, res, 800);
                return;
            }
            else
                ip = req.headers['x-forwarded-for'];
        else
            ip = req.connection.remoteAddress;

        // Extract IPv4 from IPv6 hybrid notation
        if (ip.indexOf("::ffff:") > -1) {
            var ipFiltered = ip.split(":");
            ip = ipFiltered[ipFiltered.length-1];
            logger.debug("Hybrid IPv6 IP filtered: " + ip);
        }
        logger.debug("Add agent with automatic IP: " + ip);
    }
    req.body.ip = ip;

    var data_request = {'function': 'POST/agents/insert', 'arguments': {}};
    var filters = {'name':'names', 'ip':'ips', 'id':'numbers', 'key': 'ossec_key', 'force':'numbers'};

    if (!filter.check(req.body, filters, req, res))  // Filter with error
        return;

    data_request['arguments']['id'] = req.body.id;
    data_request['arguments']['name'] = req.body.name;
    data_request['arguments']['ip'] = req.body.ip;
    data_request['arguments']['key'] = req.body.key;
    if ('force' in req.body){
        data_request['arguments']['force'] = req.body.force;
    }

    if ('id' in req.body && 'name' in req.body && 'ip' in req.body && 'key' in req.body){
        execute.exec(python_bin, [ossec_control], data_request, function (data) { res_h.send(req, res, data); });
    }else
        res_h.bad_request(req, res, 604, "Missing fields. Mandatory fields: id, name, ip, key");
})



/**
 * @api {get} /agents/stats/distinct Get distinct fields in agents
 * @apiName GetdistinctAgents
 * @apiGroup Stats
 *
 * @apiParam {Number} [offset] First element to return in the collection.
 * @apiParam {Number} [limit=500] Maximum number of elements to return.
 * @apiParam {String} [sort] Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
 * @apiParam {String} [search] Looks for elements with the specified string.
 * @apiParam {String} [fields] List of fields affecting the operation.
 * @apiParam {String} [select] List of selected fields.
 *
 * @apiDescription Returns all the different combinations that agents have for the selected fields. It also indicates the total number of agents that have each combination.
 *
 * @apiExample {curl} Example usage:
 *     curl -u foo:bar -k -X GET "https://127.0.0.1:55000/agents/stats/distinct?pretty&fields=os.platform"
 *
 */
router.get('/stats/distinct', cache(), function (req, res) {
    logger.debug(req.connection.remoteAddress + " GET /agents/stats/distinct");

    req.apicacheGroup = "manager";

    var data_request = { 'function': '/agents/stats/distinct', 'arguments': {} };
    var filters = {
        'offset': 'numbers', 'limit': 'numbers', 'select': 'select_param', 'sort': 'sort_param',
        'search': 'search_param', 'fields': 'select_param'
    };

    if ('fields' in req.query)
        data_request['arguments']['db_select'] = filter.select_param_to_json(req.query.fields);
    if ('select' in req.query)
        data_request['arguments']['filter_fields'] = filter.select_param_to_json(req.query.select);
    if ('offset' in req.query)
        data_request['arguments']['offset'] = Number(req.query.offset);
    if ('limit' in req.query)
        data_request['arguments']['limit'] = Number(req.query.limit);
    if ('sort' in req.query)
        data_request['arguments']['sort'] = filter.sort_param_to_json(req.query.sort);
    if ('search' in req.query)
        data_request['arguments']['search'] = filter.search_param_to_json(req.query.search);

    execute.exec(python_bin, [ossec_control], data_request, function (data) { res_h.send(req, res, data); });
})

module.exports = router;