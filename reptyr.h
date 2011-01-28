#define REPTYR_VERSION "0.1"

int attach_child(pid_t pid, const char *pty);
void die(const char *msg, ...);
void debug(const char *msg, ...);
void error(const char *msg, ...);
