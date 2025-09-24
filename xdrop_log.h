#ifndef XDROP_LOG_H
#define XDROP_LOG_H
#ifdef XDROP_DEBUG
#define DEBUG_OUT(format, args...) \
fprintf(stderr, "[%s:%d %s]", __FILE__, __LINE__, __func__); \
fprintf(stderr, format, ##args)
#else
#define DEBUG_OUT(format, args...) do{}while(0)
#endif
#define ERR_OUT(format, args...) fprintf(stderr, format, ##args)
#endif
