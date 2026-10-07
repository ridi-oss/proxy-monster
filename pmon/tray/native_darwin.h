#include <stdbool.h>

#define PM_LOGIN_UNSUPPORTED 0
#define PM_LOGIN_OFF 1
#define PM_LOGIN_ON 2

bool pm_notifications_init(void);
bool pm_notify(const char *ident, const char *title, const char *body, const char *key);
int pm_login_item_status(void);
char *pm_set_login_item(bool on);
bool pm_pref_bool(const char *key);
void pm_set_pref_bool(const char *key, bool value);
void pm_activate_pid(int pid);
void pm_url_init(void);
char *pm_pref_string(const char *key);
void pm_set_pref_string(const char *key, const char *value);
char *pm_preferred_languages(void);
void pm_set_appearance(void *window, int mode);
