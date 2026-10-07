#include <stdbool.h>

bool pm_updates_configured(void);
bool pm_updates_auto(void);
bool pm_updates_forced(void);
bool pm_updater_start(void);
void pm_updater_check(void);
void pm_updater_set_auto(bool on);
void pm_updater_install(void);
