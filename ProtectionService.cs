using Android.App;
using Android.Content;
using Android.OS;
using Android.Widget;
using System;
using System.Collections.Generic;
using System.Linq;
using Android.Runtime;

namespace app1;

[Service]
public class ProtectionService : Service
{
    private Handler handler;
    private System.Timers.Timer scanTimer;
    private const string CHANNEL_ID = "ProtectionChannel";

    public override IBinder OnBind(Intent intent)
    {
        return null;
    }

    public override StartCommandResult OnStartCommand(Intent intent, StartCommandFlags flags, int startId)
    {
        CreateNotificationChannel();
        StartForegroundService();
        StartPeriodicScans();
        return StartCommandResult.Sticky;
    }

    private void CreateNotificationChannel()
    {
        if (Build.VERSION.SdkInt >= BuildVersionCodes.O)
        {
            var channel = new NotificationChannel(
                CHANNEL_ID,
                "حماية النظام",
                NotificationImportance.Low
            )
            {
                Description = "خدمة مراقبة وحماية النظام"
            };

            var notificationManager = GetSystemService(NotificationService) as NotificationManager;
            notificationManager?.CreateNotificationChannel(channel);
        }
    }

    private void StartForegroundService()
    {
        var intent = new Intent(this, typeof(MainActivity));
        var pendingIntent = PendingIntent.GetActivity(this, 0, intent, PendingIntentFlags.UpdateCurrent | PendingIntentFlags.Immutable);

        var notification = new Notification.Builder(this, CHANNEL_ID)
            .SetContentTitle("حماية النظام نشطة")
            .SetContentText("جاري المراقبة الدورية للتطبيقات والتهديدات")
            .SetSmallIcon(Android.Resource.Drawable.IcDialogInfo)
            .SetContentIntent(pendingIntent)
            .SetAutoCancel(true)
            .Build();

        StartForeground(1, notification);
    }

    private void StartPeriodicScans()
    {
        handler = new Handler(Looper.MainLooper);

        scanTimer = new System.Timers.Timer(300000); // 5 دقائق
        scanTimer.Elapsed += (s, e) => RunSecurityScan();
        scanTimer.AutoReset = true;
        scanTimer.Start();

        // فحص أول فوري
        RunSecurityScan();
    }

    private void RunSecurityScan()
    {
        try
        {
            var pm = PackageManager;
            var threats = new List<string>();

            // فحص التطبيقات المثبتة الجديدة
            var packages = pm.GetInstalledPackages(PackageInfoFlags.RequestedPermissions);
            var dangerousApps = new List<string>();

            string enabledAccessibility = Android.Provider.Settings.Secure.GetString(ContentResolver, Android.Provider.Settings.Secure.EnabledAccessibilityServices) ?? string.Empty;

            string[] dangerousPerms = new[] {
                Android.Manifest.Permission.ReadSms,
                Android.Manifest.Permission.SendSms,
                Android.Manifest.Permission.ReadContacts,
                Android.Manifest.Permission.ReadCallLog,
                Android.Manifest.Permission.WriteCallLog,
                Android.Manifest.Permission.CallPhone,
                Android.Manifest.Permission.RecordAudio,
                Android.Manifest.Permission.Camera,
                Android.Manifest.Permission.AccessFineLocation,
                Android.Manifest.Permission.AccessCoarseLocation
            };

            foreach (var pkg in packages)
            {
                try
                {
                    // تحقق من التطبيقات الجديدة من مصادر غير معروفة
                    var installer = pm.GetInstallerPackageName(pkg.PackageName);
                    if (string.IsNullOrEmpty(installer) || installer.Contains("unknown"))
                    {
                        dangerousApps.Add(pkg.PackageName);
                        threats.Add($"⚠️ تطبيق من مصدر غير معروف: {pkg.PackageName}");
                    }

                    // فحص خدمات الوصول المشبوهة
                    if (!string.IsNullOrEmpty(enabledAccessibility) && enabledAccessibility.Contains(pkg.PackageName))
                    {
                        threats.Add($"🔐 تحذير: {pkg.PackageName} لديها خدمة وصول مفعلة");
                    }

                    // فحص الأذونات الخطرة
                    if (pkg.RequestedPermissions != null)
                    {
                        var riskyPerms = pkg.RequestedPermissions.Where(p => dangerousPerms.Contains(p)).ToList();
                        if (riskyPerms.Count > 3)
                        {
                            threats.Add($"⚠️ {pkg.PackageName} يطلب {riskyPerms.Count} أذونات خطرة");
                        }
                    }
                }
                catch { }
            }

            // كشف الروت
            if (DetectRoot())
            {
                threats.Add("🚨 تحذير حرج: روت مكتشف على الجهاز!");
            }

            // كشف محاكي
            if (IsEmulator())
            {
                threats.Add("ℹ️ تم اكتشاف بيئة محاكاة - قد تكون أقل أماناً");
            }

            // إذا كانت هناك تهديدات، أصدر إشعاراً
            if (threats.Count > 0)
            {
                SendAlert(threats);
            }
        }
        catch (Exception ex)
        {
            Android.Util.Log.Error("ProtectionService", $"خطأ في الفحص: {ex.Message}");
        }
    }

    private bool DetectRoot()
    {
        try
        {
            string[] paths = new[] {
                "/sbin/su",
                "/system/bin/su",
                "/system/xbin/su",
                "/system/app/Superuser.apk",
                "/system/app/SuperSU.apk",
                "/system/bin/.ext/.su",
                "/data/adb/magisk"
            };

            foreach (var p in paths)
            {
                if (System.IO.File.Exists(p)) return true;
            }

            try
            {
                var runtime = Java.Lang.Runtime.GetRuntime();
                var proc = runtime.Exec(new string[] { "/system/xbin/which", "su" });
                var isr = new System.IO.StreamReader(proc.InputStream);
                var output = isr.ReadToEnd();
                if (!string.IsNullOrWhiteSpace(output)) return true;
            }
            catch { }

            return false;
        }
        catch { return false; }
    }

    private bool IsEmulator()
    {
        return (Build.Fingerprint.Contains("generic") ||
                Build.Device.Contains("generic") ||
                Build.Hardware.Contains("ranchu") ||
                Build.Product.Contains("emulator") ||
                Android.OS.Build.Model.Contains("Android SDK"));
    }

    private void SendAlert(List<string> threats)
    {
        try
        {
            var notificationManager = GetSystemService(NotificationService) as NotificationManager;
            var intent = new Intent(this, typeof(MainActivity));
            var pendingIntent = PendingIntent.GetActivity(this, 1, intent, PendingIntentFlags.UpdateCurrent | PendingIntentFlags.Immutable);

            var title = threats.Count > 0 ? "تهديدات محتملة مكتشفة" : "حالة حسنة";
            var text = string.Join(" | ", threats.Take(3));

            var notification = new Notification.Builder(this, CHANNEL_ID)
                .SetContentTitle(title)
                .SetContentText(text)
                .SetSmallIcon(Android.Resource.Drawable.IcDialogAlert)
                .SetContentIntent(pendingIntent)
                .SetAutoCancel(true)
                .Build();

            notificationManager?.Notify(2, notification);
        }
        catch (Exception ex)
        {
            Android.Util.Log.Error("ProtectionService", $"خطأ في الإشعار: {ex.Message}");
        }
    }

    public override void OnDestroy()
    {
        base.OnDestroy();
        scanTimer?.Stop();
        scanTimer?.Dispose();
    }
}
