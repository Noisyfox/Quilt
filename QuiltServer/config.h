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
		const char* server_host;
		int server_port;
		const char* mocking_host;
		const char* mocking_ip;
		const char* password;
		int local_port;
	} config_t;

	int parse_config(int argc, char** argv, config_t* out);

#ifdef __cplusplus
};
#endif

#endif //Q_CFG_H
