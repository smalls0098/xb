package xb

import (
	"testing"
	"time"
)

func Test_Encode(t *testing.T) {
	ts := time.Now().Unix()
	ts = 1710927309
	res := Encode(
		"device_platform=webapp&aid=6383&channel=channel_pc_web&aweme_id=7346145148188904742&pc_client_type=3&version_code=190500&version_name=19.5.0&cookie_enabled=true&screen_width=1792&screen_height=1120&browser_language=zh-CN&browser_platform=MacIntel&browser_name=Chrome&browser_version=104.0.5112.102&browser_online=true&engine_name=Blink&engine_version=104.0.5112.102&os_name=Mac+OS&os_version=10.15.7&cpu_core_num=12&device_memory=8&platform=PC&downlink=9.6&effective_type=4g&round_trip_time=0&webid=7209940127916459575&msToken=191ZZJ5jsfzviU7JMotGDULg3e8hVIh9B9CqqeNmFOMF7qHrbmi_44Vri00ssGlSI46oyGcOPMVtIFqdze7bYWGm40CDtmqJHV_YterqNVoC220dvjMP",
		"",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) douyin/3.4.0 Chrome/104.0.5112.102 Electron/20.1.0-tt.4.release.douyin.155 TTElectron/20.1.0-tt.4.release.douyin.155 Safari/537.36 awemePcClient/3.4.0 buildId/11509980 osName/Mac",
		uint32(ts),
	)
	t.Log(res, res == "DFSzswVO/72ANVartLGTYN7TlqCM")
}

func Test_Decode(t *testing.T) {
	res, err := Decode("DFSzswVO/72ANVartLGTYN7TlqCM")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", res)
}
