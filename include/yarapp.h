#pragma once

#include <string>
#include <yara.h>
#include <functional>

class yarapp
{
public:
	yarapp();
	~yarapp();

	bool add_string(const std::string& rule);
	void finalize();

	void set_scan_callback(std::function<int(int, void *, void *)>);

	void scan_memory(unsigned char *buffer, size_t buffer_len,void *user_data);
private:
	std::function<int(int, void *, void *)> scan_callback_;
	YR_COMPILER *compiler_;
	YR_RULES *rules_;
};