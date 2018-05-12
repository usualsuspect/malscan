#pragma once

#include <string>
#include <yara.h>

class yarapp
{
public:
	yarapp();
	~yarapp();

	bool add_string(const std::string& rule);
	void finalize();

	void scan_memory(unsigned char *buffer, size_t buffer_len);
private:
	static int scan_callback(int message, void *msg_data, void *user_data);
	YR_COMPILER *compiler_;
	YR_RULES *rules_;
};