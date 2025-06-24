package de.cyberkatze.iroot;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ApplicationInfo;
import android.os.Build;

import org.apache.cordova.LOG;

import java.io.File;
import java.util.List;
import org.json.JSONObject;
import org.json.JSONException;

public class InternalRootDetection {

    // ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---

    public boolean isRooted(final Context context) {
        boolean c1 = isExistBuildTags();
        boolean c2 = doesSuperuserApkExist();
        boolean c3 = isExistSUPath();
        boolean c4 = checkDirPermissions();
        boolean c5 = checkExecutingCommands();
        boolean c6 = checkInstalledPackages(context);
        boolean c7 = checkforOverTheAirCertificates();
        // boolean c8 = isRunningOnEmulator();
        boolean c9 = searchForMagisk(context);
        boolean c10 = checkForRootFiles();
        boolean c11 = checkForBusyBox();
        boolean c12 = checkForDangerousProps();
        boolean c13 = checkForRootManagementApps(context);
        boolean c14 = checkMagiskProcess();
        boolean c15 = checkGetProp();
        boolean c16 = checkMounts();
        boolean c17 = isBootloaderUnlocked();
        // boolean c18 = isSelinuxEnforcing();
        // boolean c19 = isOfficialFirmware();

        LOG.d(Constants.LOG_TAG, "check c1 = isExistBuildTags: " + c1);
        LOG.d(Constants.LOG_TAG, "check c2 = doesSuperuserApkExist: " + c2);
        LOG.d(Constants.LOG_TAG, "check c3 = isExistSUPath: " + c3);
        LOG.d(Constants.LOG_TAG, "check c4 = checkDirPermissions: " + c4);
        LOG.d(Constants.LOG_TAG, "check c5 = checkExecutingCommands: " + c5);
        LOG.d(Constants.LOG_TAG, "check c6 = checkInstalledPackages: " + c6);
        LOG.d(Constants.LOG_TAG, "check c7 = checkforOverTheAirCertificates: " + c7);
        // LOG.d(Constants.LOG_TAG, "check c8 = isRunningOnEmulator: " + c8);
        LOG.d(Constants.LOG_TAG, "check c9 = searchForMagisk: " + c9);

        boolean result = c1 || c2 || c3 || c4 || c5 || c6 || c7 || c9 || c10 || c11 || c12 || c13 || c14 || c15 || c16 || c17;

        LOG.d(Constants.LOG_TAG, String.format("[checkDirPermissions] result: %s", result));

        return result;
    }

    public boolean isRootedWithEmulator(final Context context) {
        boolean c1 = isExistBuildTags();
        boolean c2 = doesSuperuserApkExist();
        boolean c3 = isExistSUPath();
        boolean c4 = checkDirPermissions();
        boolean c5 = checkExecutingCommands();
        boolean c6 = checkInstalledPackages(context);
        boolean c7 = checkforOverTheAirCertificates();
        boolean c8 = isRunningOnEmulator();
        boolean c9 = searchForMagisk(context);
        boolean c10 = checkForRootFiles();
        boolean c11 = checkForBusyBox();
        boolean c12 = checkForDangerousProps();
        boolean c13 = checkForRootManagementApps(context);
        boolean c14 = checkMagiskProcess();
        boolean c17 = isBootloaderUnlocked();
        // boolean c18 = isSelinuxEnforcing();
        // boolean c19 = isOfficialFirmware();

        LOG.d(Constants.LOG_TAG, "check c1 = isExistBuildTags: " + c1);
        LOG.d(Constants.LOG_TAG, "check c2 = doesSuperuserApkExist: " + c2);
        LOG.d(Constants.LOG_TAG, "check c3 = isExistSUPath: " + c3);
        LOG.d(Constants.LOG_TAG, "check c4 = checkDirPermissions: " + c4);
        LOG.d(Constants.LOG_TAG, "check c5 = checkExecutingCommands: " + c5);
        LOG.d(Constants.LOG_TAG, "check c6 = checkInstalledPackages: " + c6);
        LOG.d(Constants.LOG_TAG, "check c7 = checkforOverTheAirCertificates: " + c7);
        LOG.d(Constants.LOG_TAG, "check c8 = isRunningOnEmulator: " + c8);
        LOG.d(Constants.LOG_TAG, "check c9 = searchForMagisk: " + c9);

        boolean result = c1 || c2 || c3 || c4 || c5 || c6 || c7 || c8 || c9 || c10 || c11 || c12 || c13 || c17;

        LOG.d(Constants.LOG_TAG, String.format("[checkDirPermissions] result: %s", result));

        return result;
    }

    public Object WhatisRooted(final String action, final Context context) {
        Object result = false; // Initialize result as a boolean
        switch (action) {
            case "isExistBuildTags": 
                result = isExistBuildTags();
                break;
            case "doesSuperuserApkExist": 
                result = doesSuperuserApkExist();
                break;
            case "isExistSUPath": 
                result = isExistSUPath();
                break;
            case "checkDirPermissions": 
                result = checkDirPermissions();
                break;
            case "checkExecutingCommands": 
                result = checkExecutingCommands();
                break;
            case "checkInstalledPackages": 
                result = checkInstalledPackages(context);
                break;
            case "checkforOverTheAirCertificates": 
                result = checkforOverTheAirCertificates();
                break;
            case "isRunningOnEmulator": 
                result = isRunningOnEmulator();
                break;
            case "simpleCheckEmulator": 
            case "simpleCheckSDKBF86": 
            case "simpleCheckQRREFPH": 
            case "simpleCheckBuild": 
            case "checkGenymotion": 
            case "checkGeneric": 
            case "checkGoogleSDK": 
                result = WhatisRunningOnEmulator(action);
                break;
            case "getTrue": 
                result = getTrue(); // Call getTrue without arguments
                break;
            case "listFilesInDirectory": 
                result = listFilesInDirectory(action); // Ensure action is a directory path
                break;
            default: 
                LOG.e(Constants.LOG_TAG, String.format("[WhatisRooted] action: %s", action));
        }
        return result;
    }

    /**
     * Checks whether any of the system directories are writable or the /data directory is readable.
     * This test will usually result in a false negative on rooted devices.
     */
    private boolean checkDirPermissions() {
        boolean isWritableDir;
        boolean isReadableDataDir;
        boolean result = false;

        for (String dirName : Constants.PATHS_THAT_SHOULD_NOT_BE_WRITABLE) {
            final File currentDir = new File(dirName);

            isWritableDir = currentDir.exists() && currentDir.canWrite();
            isReadableDataDir = (dirName.equals("/data") && currentDir.canRead());

            if (isWritableDir || isReadableDataDir) {
                LOG.d(Constants.LOG_TAG, String.format("[checkDirPermissions] check [%s] => [isWritable:%s][isReadableData:%s]", dirName, isWritableDir, isReadableDataDir));

                result = true;
            }
        }

        LOG.d(Constants.LOG_TAG, String.format("[checkDirPermissions] result: %s", result));

        return result;
    }

    /**
     * Checking the BUILD tag for test-keys. By default, stock Android ROMs from Google are built with release-keys tags.
     * If test-keys are present, this can mean that the Android build on the device is either a developer build
     * or an unofficial Google build.
     *
     * For example: Nexus 4 is running stock Android from Google’s (Android Open Source Project) AOSP.
     * This is why the build tags show "release-keys".
     *
     * > root@android:/ # cat /system/build.prop | grep ro.build.tags
     * > ro.build.tags=release-keys
     */
    private boolean isExistBuildTags() {
        boolean result = false;

        try {
            String buildTags = Constants.ANDROID_OS_BUILD_TAGS;

            // LOG.d(Constants.LOG_TAG, String.format("[isExistBuildTags] buildTags: %s", buildTags));

            result = (buildTags != null) && buildTags.contains("test-keys");
        } catch (Exception e) {
            LOG.e(Constants.LOG_TAG, String.format("[isExistBuildTags] Error: %s", e.getMessage()));
        }

        LOG.d(Constants.LOG_TAG, String.format("[isExistBuildTags] result: %s", result));

        return result;
    }

    /**
     * Checks whether the Superuser.apk is present in the system applications.
     *
     * Superuser.apk. This package is most often looked for on rooted devices.
     * Superuser allows the user to authorize applications to run as root on the device.
     */
    private boolean doesSuperuserApkExist() {
        boolean result = false;

        for (String path : Constants.SUPER_USER_APK_FILES) {
            final File rootFile = new File(path);

            if (rootFile.exists()) {
                LOG.d(Constants.LOG_TAG, String.format("[doesSuperuserApkExist] found SU apk: %s", path));

                result = true;
            }
        }

        LOG.d(Constants.LOG_TAG, String.format("[doesSuperuserApkExist] result: %s", result));

        return result;
    }

    /**
     * Checking if SU path exist (case sensitive).
     */
    private boolean isExistSUPath() {
        final String[] pathsArray = Constants.SU_PATHES.toArray(new String[0]);

        boolean result = false;

        for (final String path : pathsArray) {
            final String completePath = path + "su";
            final File suPath = new File(completePath);
            final boolean fileExists = suPath.exists();

            if (fileExists) {
                LOG.d(Constants.LOG_TAG, String.format("[isExistSUPath] binary [%s] detected!", path));

                result = true;
            }
        }

        LOG.d(Constants.LOG_TAG, String.format("[isExistSUPath] result: %s", result));

        return result;
    }

    /**
     * Checks for installed packages which are known to be present on rooted devices.
     *
     * @param context Used for accessing the package manager.
     */
    private boolean checkInstalledPackages(final Context context) {
        final PackageManager pm = context.getPackageManager();
        final List<PackageInfo> installedPackages = pm.getInstalledPackages(0);

        int rootOnlyAppCount = 0;

        for (PackageInfo packageInfo : installedPackages) {
            final String packageName = packageInfo.packageName;

            if (Constants.BLACKLISTED_PACKAGES.contains(packageName)) {
                LOG.d(Constants.LOG_TAG, String.format("[checkInstalledPackages] Package [%s] found in BLACKLISTED_PACKAGES", packageName));

                return true;
            }

            if (Constants.ROOT_ONLY_APPLICATIONS.contains(packageName)) {
                LOG.d(Constants.LOG_TAG, String.format("[checkInstalledPackages] Package [%s] found in ROOT_ONLY_APPLICATIONS", packageName));

                rootOnlyAppCount += 1;
            }

            // Check to see if the Cydia Substrate exists.
            if (Constants.CYDIA_SUBSTRATE_PACKAGE.equals(packageName)) {
                LOG.d(Constants.LOG_TAG, String.format("[checkInstalledPackages] Package [%s] found in CYDIA_SUBSTRATE_PACKAGE", packageName));

                rootOnlyAppCount += 1;
            }
        }

        LOG.d(Constants.LOG_TAG, String.format("[checkInstalledPackages] count of root-only apps: %s", rootOnlyAppCount));

        boolean result = rootOnlyAppCount > 2; // todo: why?

        LOG.d(Constants.LOG_TAG, String.format("[checkInstalledPackages] result: %s", result));

        return result;
    }

    /**
     * Checking for Over The Air (OTA) certificates.
     *
     * By default, Android is updated OTA using public certs from Google. If the certs are not there,
     * this usually means that there is a custom ROM installed which is updated through other means.
     *
     * For example: Nexus 4 has no custom ROM and is updated through Google. Updating this device however, will probably break root.
     * > 1|bullhead:/ $ ls -l /etc/security/otacerts.zip
     * > -rw-r--r-- 1 root root 1544 2009-01-01 09:00 /etc/security/otacerts.zip
     */
    private boolean checkforOverTheAirCertificates() {
        File otacerts = new File(Constants.OTA_CERTIFICATES_PATH);
        boolean exist = otacerts.exists();
        boolean result = !exist;

        LOG.d(Constants.LOG_TAG, String.format("[checkforOverTheAirCertificates] exist: %s", exist));
        LOG.d(Constants.LOG_TAG, String.format("[checkforOverTheAirCertificates] result: %s", result));

        return result;
    }

    /**
     * Checking if possible to call SU command.
     *
     * @see <a href="https://github.com/xdhfir/xdd/blob/0df93556e4b8605057196ddb9a1c10fbc0f6e200/yeshttp/baselib/src/main/java/com/my/baselib/lib/utils/root/RootUtils.java">TODO: check xdhfir RootUtils.java</a>
     * @see <a href="https://github.com/xdhfir/xdd/blob/0df93556e4b8605057196ddb9a1c10fbc0f6e200/yeshttp/baselib/src/main/java/com/my/baselib/lib/utils/root/ExecShell.java">TODO: check xdhfir ExecShell.java</a>
     * @see <a href="https://github.com/huohong01/truck/blob/master/app/src/main/java/com/hsdi/NetMe/util/RootUtils.java">adopted huohong01 RootUtils.java</a>
     * @see <a href="https://github.com/tansiufang54/fncgss/blob/master/app/src/main/java/co/id/franknco/controller/RootUtil.java">adopted tansiufang54 RootUtils.java</a>
     */
    private boolean checkExecutingCommands() {
        boolean c1 = Utils.canExecuteCommand("/system/xbin/which su");
        boolean c2 = Utils.canExecuteCommand("/system/bin/which su");
        boolean c3 = Utils.canExecuteCommand("which su");

        boolean result = c1 || c2 || c3;

        LOG.d(Constants.LOG_TAG, String.format("[checkExecutingCommands] result [%s] => [c1:%s][c2:%s][c3:%s]", result, c1, c2, c3));

        return result;
    }

    /**
     * Simple implementation.
     * <p>
     * TODO: move in another class.
     * TODO: check this repos:
     *
     * @see <a href="https://github.com/strazzere/anti-emulator">anti-emulator</a>
     * @see <a href="https://github.com/framgia/android-emulator-detector">android-emulator-detector</a>
     * @see <a href="https://github.com/testmandy/NativeAdLibrary-master/blob/68e1a972fc746a0b51395f813f5bcf32fd619376/library/src/main/java/me/dt/nativeadlibary/util/RootUtil.java#L59">testmandy RootUtil.java</a>
     */
     public boolean isRunningOnEmulator() {
         Utils.getDeviceInfo();
         boolean simpleCheck = Build.MODEL.contains("Emulator")
             // ||Build.FINGERPRINT.startsWith("unknown") // Meizu Mx Pro will return unknown, so comment it!
             || Build.MODEL.contains("Android SDK built for x86")
             || Build.BOARD.equals("QC_Reference_Phone") //bluestacks
             || Build.HOST.startsWith("Build"); //MSI App Player

         boolean checkGenymotion = Build.MANUFACTURER.contains("Genymotion");
         boolean checkGeneric = Build.FINGERPRINT.startsWith("generic") || (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"));
         boolean checkGoogleSDK = Build.MODEL.contains("google_sdk") || "google_sdk".equals(Build.PRODUCT);

         boolean result = simpleCheck || checkGenymotion || checkGeneric || checkGoogleSDK;

         LOG.d(
             Constants.LOG_TAG,
             String.format(
                 "[isRunningOnEmulator] result [%s] => [simpleCheck:%s][checkGenymotion:%s][checkGeneric:%s][checkGoogleSDK:%s]",
                 result,
                 simpleCheck,
                 checkGenymotion,
                 checkGeneric,
                 checkGoogleSDK
             )
         );

         return result;
     }

     public boolean WhatisRunningOnEmulator(final String action) {

         Utils.getDeviceInfo();
         boolean result = false;

         switch (action) {
           case "simpleCheckEmulator": result = Build.MODEL.contains("Emulator");
           break;
           case "simpleCheckSDKBF86": result = Build.MODEL.contains("Android SDK built for x86");
           break;
           case "simpleCheckQRREFPH": result = Build.BOARD.equals("QC_Reference_Phone");
           break;
           case "simpleCheckBuild": result = Build.HOST.startsWith("Build");
           break;
           case "checkGenymotion": result = Build.MANUFACTURER.contains("Genymotion");
           break;
           case "checkGeneric": result = Build.FINGERPRINT.startsWith("generic") || (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"));
           break;
           case "checkGoogleSDK": result = Build.MODEL.contains("google_sdk") || "google_sdk".equals(Build.PRODUCT);
           break;
         }
         return result;
     }

     public JSONObject togetDeviceInfo() throws JSONException {
         Utils.getDeviceInfo();
         JSONObject objBuild = new JSONObject();
         objBuild.put("DEVICE",Build.DEVICE);
         objBuild.put("MODEL",Build.MODEL);
         objBuild.put("MANUFACTURER",Build.MANUFACTURER);
         objBuild.put("BRAND",Build.BRAND);
         objBuild.put("BOARD",Build.BOARD);
         objBuild.put("HARDWARE",Build.HARDWARE);
         objBuild.put("PRODUCT",Build.PRODUCT);
         objBuild.put("FINGERPRINT",Build.FINGERPRINT);
         objBuild.put("HOST",Build.HOST);
         // Add More info
         objBuild.put("USER",Build.USER);
         objBuild.put("OSNAME",System.getProperty("os.name"));
         objBuild.put("OSVERSION",System.getProperty("os.version"));
         objBuild.put("V.INCREMENTAL",Build.VERSION.INCREMENTAL);
         objBuild.put("V.RELEASE",Build.VERSION.RELEASE);
         objBuild.put("V.SDK_INT",Build.VERSION.SDK_INT);
         return objBuild;
    }

    public boolean searchForMagisk(final Context context) {
        final PackageManager pm = context.getPackageManager();
        final List<PackageInfo> installedPackages = pm.getInstalledPackages(0);

        boolean result = false;

        for (PackageInfo info : installedPackages) {
            final ApplicationInfo appInfo = info.applicationInfo;
            final String nativeLibraryDir = appInfo.nativeLibraryDir;

            LOG.d(Constants.LOG_TAG, "Checking App: " + nativeLibraryDir);

            final File f = new File(nativeLibraryDir + "/libstub.so");
            if (f.exists()) {
                LOG.d(Constants.LOG_TAG, "Magisk was Detected!");
                result = true;
                break;
            }
        }

        LOG.d(Constants.LOG_TAG, String.format("[searchForMagisk] result: %s", result));

        return result;
    }

    private boolean checkForRootFiles() {
        String[] rootFiles = {
            "/system/bin/magisk", // Magisk binary
            "/system/bin/magiskpolicy", // Magisk binary
            "/system/xbin/su", // Common su binary location
            "/system/bin/su", // Another common su binary location
            "/system/app/Superuser.apk", // Superuser app
            "/system/app/MagiskManager.apk" // Magisk Manager app
        };

        boolean result = false;
        for (String filePath : rootFiles) {
            File file = new File(filePath);
            if (file.exists()) {
                LOG.d(Constants.LOG_TAG, String.format("[checkForRootFiles] Root file found: %s", filePath));
                result = true;
                break;
            }
        }

        LOG.d(Constants.LOG_TAG, String.format("[checkForRootFiles] result: %s", result));
        return result;
    }

    /**
     * Checks for the presence of BusyBox, which is often installed on rooted devices.
     */
    private boolean checkForBusyBox() {
        boolean result = Utils.canExecuteCommand("busybox");
        LOG.d(Constants.LOG_TAG, String.format("[checkForBusyBox] result: %s", result));
        return result;
    }

    /**
     * Checks for dangerous system properties that may indicate a rooted device.
     */
    private boolean checkForDangerousProps() {
        String[] dangerousProps = {
            "ro.debuggable=1",
            "ro.secure=0"
        };

        boolean result = false;
        for (String prop : dangerousProps) {
            String propValue = Utils.getSystemProperty(prop.split("=")[0]);
            if (propValue != null && propValue.equals(prop.split("=")[1])) {
                LOG.d(Constants.LOG_TAG, String.format("[checkForDangerousProps] Dangerous property found: %s", prop));
                result = true;
                break;
            }
        }

        LOG.d(Constants.LOG_TAG, String.format("[checkForDangerousProps] result: %s", result));
        return result;
    }

    /**
     * Checks for the presence of root management apps.
     */
    private boolean checkForRootManagementApps(final Context context) {
        final PackageManager pm = context.getPackageManager();
        final List<PackageInfo> installedPackages = pm.getInstalledPackages(0);

        boolean result = false;
        for (PackageInfo packageInfo : installedPackages) {
            final String packageName = packageInfo.packageName;
            if (Constants.ROOT_MANAGEMENT_APPS.contains(packageName)) {
                LOG.d(Constants.LOG_TAG, String.format("[checkForRootManagementApps] Root management app found: %s", packageName));
                result = true;
                break;
            }
        }

        LOG.d(Constants.LOG_TAG, String.format("[checkForRootManagementApps] result: %s", result));
        return result;
    }

    public static boolean checkMagiskProcess() {
        return executeCommand("pidof magiskd") || executeCommand("ps -A | grep magisk");
    }

    public static boolean checkGetProp() {
        String prop = executeCommandAndReturn("getprop ro.build.tags");
        return prop != null && prop.contains("test-keys"); // test-keys indica que el dispositivo podría estar modificado
    }

    private static boolean executeCommand(String command) {
        try {
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            return in.readLine() != null;
        } catch (IOException e) {
            LOG.e(Constants.LOG_TAG, String.format("[executeCommand] Error: %s", e.getMessage()));
            return false;
        }
    }

    private static String executeCommandAndReturn(String command) {
        try {
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            return in.readLine();
        } catch (IOException e) {
            return null;
        }
    }

    public static boolean checkMounts() {
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/mounts"));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains(" /system ") && line.contains(" rw,")) {
                    return true; // Root detectado
                }
            }
            reader.close();
        } catch (IOException e) {
            return false;
        }
        return false;
    }

    public boolean getTrue() {
        return true;
    }

    public List<String> listFilesInDirectory(String directoryPath) {
        List<String> fileList = new ArrayList<>();
        File directory = new File(directoryPath);

        if (directory.exists() && directory.isDirectory()) {
            File[] files = directory.listFiles();
            if (files != null) {
                for (File file : files) {
                    fileList.add(file.getName());
                    LOG.d(Constants.LOG_TAG, String.format("[listFilesInDirectory] Found: %s", file.getName()));
                }
            }
        } else {
            LOG.e(Constants.LOG_TAG, String.format("[listFilesInDirectory] Directory not found: %s", directoryPath));
        }

        return fileList;
    }

    public static boolean isBootloaderUnlocked() {
        String bootloader = getSystemProperty("ro.boot.verifiedbootstate");
        return bootloader != null && !bootloader.equals("green"); // "green" es seguro
    }

    public static boolean isSelinuxEnforcing() {
        String selinuxStatus = getSystemProperty("ro.boot.selinux");
        return selinuxStatus != null && selinuxStatus.equals("enforcing");
    }

    public static boolean isOfficialFirmware() {
        String buildTags = getSystemProperty("ro.build.tags");
        return buildTags != null && !buildTags.contains("test-keys");
    }

    private static String getSystemProperty(String propName) {
        try {
            Process process = Runtime.getRuntime().exec("getprop " + propName);
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            return in.readLine();
        } catch (IOException e) {
            return null;
        }
    }
}
