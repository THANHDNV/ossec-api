var logger = require('../helpers/logger');
var errors = require('../helpers/errors');
var timeout = 240; // seconds

/**
 * Exec command.
 * It returns (callback) always a JSON.
 * Input
 *   Error: {'error': !=0, 'message': 'Error description'}
 *   OK: {'error': 0, 'data' = 'cmd output'}
 * Output
 *   Error: {'error': !=0, 'message': 'Error description'}
 *   OK: {'error': 0, 'data' = 'cmd output'}
 */
exports.exec = function(cmd, args, stdin, callback) {
    const child_process  = require('child_process');

    if (stdin != null)
        stdin['ossec_path'] = config.ossec_path;

    // log
    var full_cmd = "CMD - Command: " + cmd + " args:" + args.join(' ') + " stdin:" + JSON.stringify(stdin);
    logger.debug(full_cmd);

    const child = child_process.spawn(cmd, args);

    var output = [];
    var error = false;
    var close = false;
    var tout = false;

    setTimeout(function(){
        logger.debug("Sending SIGTERM to " + full_cmd);
        child.kill('SIGTERM');
        tout = true;
    }, timeout*1000);

    // Delay to prevent write stdin when the pipe is closed.
    setTimeout(function(){
        if (!close){
            child.stdin.setEncoding('utf-8');
            child.stdin.write(JSON.stringify(stdin) +"\n");
        }
    }, 50);

    child.stdout.on('data', (chunk) => {
        output.push(chunk)
        //logger.debug("Chunk: " + Buffer.byteLength(chunk, 'utf8') + " bytes");
    });

    child.on('error', function(err) {
        logger.error("CMD - Error executing command: " + err);
        error = true;
        callback({"error": 1, "message": errors.description(1)});  // Error executing internal command
    });

    child.on('close', (code) => {
        logger.debug("CMD - Exit code: " + code);
        close = true;
        if (!error){
            var json_result = {};

            if (code != 0){  // Exit code must be 0
                if (tout)
                    json_result = {"error": 1, "message": errors.description(1) + ". Timeout exceeded (" + timeout + "s)."};  // Error executing internal command
                else
                    json_result = {"error": 1, "message": errors.description(1) + ". Exit code: " + code};  // Error executing internal command
            }
            else{
                var json_cmd = {}
                // Check JSON
                var stdout = output.join('');
                logger.debug("CMD - STDOUT:\n---\n" + stdout + "\n---");
                logger.debug("CMD - STDOUT: " + Buffer.byteLength(stdout, 'utf8') + " bytes");
                json_cmd = tryParseJSON(stdout)

                if (!json_cmd){
                    logger.debug("CMD - STDOUT NOT JSON");
                    json_result = {"error": 2, "message": errors.description(2)}; // OUTPUT Not JSON
                }
                else{
                    // Check JSON content
                    if ( json_cmd.hasOwnProperty('error') && ( json_cmd.hasOwnProperty('message') || json_cmd.hasOwnProperty('data') ) ){

                        json_result.error = json_cmd.error;

                        if ( json_cmd.hasOwnProperty('data') )
                            json_result.data = json_cmd.data;

                        if ( json_cmd.hasOwnProperty('message') )
                            json_result.message = json_cmd.message;
                    }
                    else{
                        json_result = {"error": 1, "message": errors.description(1) + ". Wrong keys"}; // JSON Wrong keys
                        logger.error("CMD - Wrong keys: " + Object.keys(json_cmd));
                    }
                }
            }
            callback(json_result);
        }
    });

}

function tryParseJSON (jsonString){
    logger.debug(jsonString)
    try {
        var o = JSON.parse(jsonString);
        logger.debug(o)
        if (o && typeof o === "object" && o !== null) {
            return o;
        }
    }
    catch (e) { }

    return false;
};
