cordova.define('cordova/plugin_list', function(require, exports, module) {
  module.exports = [
    {
      "id": "cordova-plugin-device.device",
      "file": "plugins/cordova-plugin-device/www/device.js",
      "pluginId": "cordova-plugin-device",
      "clobbers": [
        "device"
      ]
    },
    {
      "id": "cordova-plugin-outline.OutlinePlugin",
      "file": "plugins/cordova-plugin-outline/outlinePlugin.js",
      "pluginId": "cordova-plugin-outline",
      "clobbers": [
        "cordova.plugins.outline"
      ]
    },
    {
      "id": "cordova-plugin-splashscreen.SplashScreen",
      "file": "plugins/cordova-plugin-splashscreen/www/splashscreen.js",
      "pluginId": "cordova-plugin-splashscreen",
      "clobbers": [
        "navigator.splashscreen"
      ]
    },
    {
      "id": "cordova-plugin-statusbar.statusbar",
      "file": "plugins/cordova-plugin-statusbar/www/statusbar.js",
      "pluginId": "cordova-plugin-statusbar",
      "clobbers": [
        "window.StatusBar"
      ]
    },
    {
      "id": "cordova-plugin-clipboard.Clipboard",
      "file": "plugins/cordova-plugin-clipboard/www/clipboard.js",
      "pluginId": "cordova-plugin-clipboard",
      "clobbers": [
        "cordova.plugins.clipboard"
      ]
    },
    {
      "id": "cordova-webintent.WebIntent",
      "file": "plugins/cordova-webintent/www/webintent.js",
      "pluginId": "cordova-webintent",
      "clobbers": [
        "WebIntent"
      ]
    }
  ];
  module.exports.metadata = {
    "cordova-custom-config": "5.1.0",
    "cordova-plugin-device": "2.0.3",
    "cordova-plugin-outline": "0.0.0",
    "cordova-plugin-splashscreen": "5.0.3",
    "cordova-plugin-statusbar": "2.4.3",
    "cordova-plugin-whitelist": "1.3.4",
    "cordova-plugin-clipboard": "2.0.0",
    "cordova-webintent": "2.0.0"
  };
});