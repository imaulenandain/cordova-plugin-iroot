var exec = require('cordova/exec');

module.exports = {
    isChecklistValid: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'isRooted', []);
    },
    isRootedWithBusyBox: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'isRootedWithBusyBox', []);
    },
    detectRootManagementApps: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'detectRootManagementApps', []);
    },
    detectPotentiallyDangerousApps: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'detectPotentiallyDangerousApps', []);
    },
    detectTestKeys: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'detectTestKeys', []);
    },
    checkForBusyBoxBinary: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'checkForBusyBoxBinary', []);
    },
    checkForSuBinary: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'checkForSuBinary', []);
    },
    checkSuExists: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'checkSuExists', []);
    },
    checkForRWPaths: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'checkForRWPaths', []);
    },
    checkForDangerousProps: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'checkForDangerousProps', []);
    },
    checkForRootNative: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'checkForRootNative', []);
    },
    detectRootCloakingApps: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'detectRootCloakingApps', []);
    },
    isSelinuxFlagInEnabled: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'isSelinuxFlagInEnabled', []);
    },
    isExistBuildTags: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'isExistBuildTags', []);
    },
    doesSuperuserApkExist: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'doesSuperuserApkExist', []);
    },
    isExistSUPath: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'isExistSUPath', []);
    },
    checkDirPermissions: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'checkDirPermissions', []);
    },
    checkExecutingCommands: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'checkExecutingCommands', []);
    },
    checkInstalledPackages: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'checkInstalledPackages', []);
    },
    checkforOverTheAirCertificates: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'checkforOverTheAirCertificates', []);
    },
    isRunningOnEmulator: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'isRunningOnEmulator', []);
    },
    simpleCheckEmulator: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'simpleCheckEmulator', []);
    },
    simpleCheckSDKBF86: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'simpleCheckSDKBF86', []);
    },
    simpleCheckQRREFPH: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'simpleCheckQRREFPH', []);
    },
    simpleCheckBuild: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'simpleCheckBuild', []);
    },
    checkGenymotion: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'checkGenymotion', []);
    },
    checkGeneric: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'checkGeneric', []);
    },
    checkGoogleSDK: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'checkGoogleSDK', []);
    },
    togetDeviceInfo: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'togetDeviceInfo', []);
    },
    isRootedWithEmulator: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'isRootedWithEmulator', []);
    },
    isRootedWithBusyBoxWithEmulator: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'isRootedWithBusyBoxWithEmulator', []);
    },
    getTrue: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'getTrue', []);
    },
    listFilesInDirectory: function(onSuccess, onError) {
        exec(onSuccess, onError, 'IChecklistPlugin', 'listFilesInDirectory', []);
    },
};
