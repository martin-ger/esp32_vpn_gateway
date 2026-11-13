/* Web UI page templates - split into per-page files */

#include "pages/page_index.h"
#include "pages/page_config.h"
#include "pages/page_mappings.h"
#include "pages/page_firewall.h"
#include "pages/page_vpn.h"
#if CONFIG_WG_SERVER
#include "pages/page_wgserver.h"
#endif
#include "pages/page_setup.h"
#include "pages/page_scan.h"
