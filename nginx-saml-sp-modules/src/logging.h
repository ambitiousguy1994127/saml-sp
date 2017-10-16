#include <ngx_core.h>

#define LOG_PREFIX 			"[OPENIAM]: "	// Logging Prefix [OPENIAM]: Errorlog
#define CORE_MAX_ERROR_STR 	4096			// If the logging message size exceeds this limit, the message will be truncated

#define logEmerg(log,  ...) 	myCoreLog(NGX_LOG_EMERG,  log, __VA_ARGS__)
#define logAlert(log,  ...) 	myCoreLog(NGX_LOG_ALERT,  log, __VA_ARGS__)
#define logCrit(log,   ...) 	myCoreLog(NGX_LOG_CRIT,   log, __VA_ARGS__)
#define logError(log,  ...) 	myCoreLog(NGX_LOG_ERR, 	  log, __VA_ARGS__)
#define logWarn(log,   ...) 	myCoreLog(NGX_LOG_WARN,   log, __VA_ARGS__)
#define logNotice(log, ...) 	myCoreLog(NGX_LOG_NOTICE, log, __VA_ARGS__)
#define logInfo(log,   ...) 	myCoreLog(NGX_LOG_INFO,   log, __VA_ARGS__)
#define logDebug(log,  ...) 	myCoreLog(NGX_LOG_DEBUG,  log, __VA_ARGS__)
    

#if (NGX_HAVE_VARIADIC_MACROS)
	void myCoreLog(ngx_uint_t level, ngx_log_t *log, ngx_err_t err, const char *fmt, ...);
#else
	void myCoreLog(ngx_uint_t level, ngx_log_t *log, ngx_err_t err, const char *fmt, va_list args);
#endif
