module github.com/ridi-oss/proxy-monster/pmon/tray

go 1.26.0

require (
	fyne.io/systray v1.12.2
	github.com/jchv/go-webview2 v0.0.0-20260205173254-56598839c808
	github.com/ridi-oss/proxy-monster/pmon v0.0.0
	github.com/webview/webview_go v0.0.0-20240831120633-6173450d4dd6
	golang.org/x/sys v0.47.0
)

require (
	github.com/aws/aws-sdk-go-v2 v1.47.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/athena v1.66.1 // indirect
	github.com/aws/smithy-go v1.28.1 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/jchv/go-winloader v0.0.0-20250406163304-c1995be93bd1 // indirect
	github.com/pelletier/go-toml/v2 v2.4.3 // indirect
	github.com/ridi-oss/proxy-monster/mysqlwire v0.1.5 // indirect
)

// In-repo module: resolve locally (no go.work needed for CI / fresh clones).
replace github.com/ridi-oss/proxy-monster/pmon => ../
