#ifndef Q_CFG_H
#define Q_CFG_H

#define CFG_NORMAL 0
#define CFG_ERR -1
#define CFG_NORMAL_EXIT -2

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct
	{
		char* server_host;
		int server_port;
		char* mocking_host;
		char* password;
		int local_port;
	} config_t;

	int parse_config(int argc, char** argv, config_t* out);

#ifdef __cplusplus
};
#endif

#endif //Q_CFG_H
