namespace app1;

[Activity(Label = "@string/app_name", MainLauncher = true)]
public class MainActivity : Activity
{
    TextView txtStatus;
    ListView listViewApps;
    private const int PERMISSION_REQUEST_CODE = 100;

    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);

        SetContentView(Resource.Layout.activity_main);

        // طلب الأذونات الديناميكية
        RequestRequiredPermissions();

        // بدء خدمة الحماية الخلفية
        var intent = new Intent(this, typeof(ProtectionService));
        if (Build.VERSION.SdkInt >= BuildVersionCodes.O)
        {
            StartForegroundService(intent);
        }
        else
        {
            StartService(intent);
        }

        var btnScan = FindViewById<Button>(Resource.Id.btnScan);
        var btnRoot = FindViewById<Button>(Resource.Id.btnRoot);
        var btnUnknown = FindViewById<Button>(Resource.Id.btnUnknown);
        txtStatus = FindViewById<TextView>(Resource.Id.txtStatus);
        listViewApps = FindViewById<ListView>(Resource.Id.listViewApps);

        btnScan.Click += (s, e) => {
            txtStatus.Text = "جارٍ فحص التطبيقات...";
            var items = ScanInstalledApps();
            listViewApps.Adapter = new ArrayAdapter<string>(this, Android.Resource.Layout.SimpleListItem1, items.ToArray());
            txtStatus.Text = $"فحص مكتمل: {items.Count} تطبيقات مفحوصة";
        };

        btnRoot.Click += (s, e) => {
            txtStatus.Text = "جارٍ فحص وجود روت...";
            var rooted = CheckRoot();
            txtStatus.Text = rooted ? "تنبيه: روت محتمل مكتشف" : "لم يُكشف روت";
        };

        btnUnknown.Click += (s, e) => {
            txtStatus.Text = "جارٍ فحص مصادر التثبيت...";
            var results = CheckUnknownInstallers();
            listViewApps.Adapter = new ArrayAdapter<string>(this, Android.Resource.Layout.SimpleListItem1, results.ToArray());
            txtStatus.Text = $"مكتمل: {results.Count} نتائج";
        };
    }

    private void RequestRequiredPermissions()
    {
        if (Build.VERSION.SdkInt >= BuildVersionCodes.M)
        {
            var permissions = new string[]
            {
                Android.Manifest.Permission.ReadSms,
                Android.Manifest.Permission.ReadContacts,
                Android.Manifest.Permission.ReadCallLog,
                Android.Manifest.Permission.Camera,
                Android.Manifest.Permission.RecordAudio,
                Android.Manifest.Permission.AccessFineLocation,
                Android.Manifest.Permission.AccessCoarseLocation,
                Android.Manifest.Permission.ReadExternalStorage,
                Android.Manifest.Permission.WriteExternalStorage,
                Android.Manifest.Permission.ReadPhoneState,
                Android.Manifest.Permission.Internet,
                Android.Manifest.Permission.AccessNetworkState
            };

            var permissionsToRequest = new List<string>();
            foreach (var permission in permissions)
            {
                if (CheckSelfPermission(permission) != Android.Content.PM.Permission.Granted)
                {
                    permissionsToRequest.Add(permission);
                }
            }

            if (permissionsToRequest.Count > 0)
            {
                RequestPermissions(permissionsToRequest.ToArray(), PERMISSION_REQUEST_CODE);
            }
        }
    }

    public override void OnRequestPermissionsResult(int requestCode, string[] permissions, Android.Content.PM.Permission[] grantResults)
    {
        base.OnRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERMISSION_REQUEST_CODE)
        {
            var granted = new List<string>();
            var denied = new List<string>();

            for (int i = 0; i < permissions.Length; i++)
            {
                if (grantResults[i] == Android.Content.PM.Permission.Granted)
                    granted.Add(permissions[i]);
                else
                    denied.Add(permissions[i]);
            }

            string message = $"منحت الأذونات: {granted.Count}\nمرفوضة: {denied.Count}";
            txtStatus.Text = message;
            Android.Widget.Toast.MakeText(this, message, Android.Widget.ToastLength.Long).Show();
        }
    }

    List<string> ScanInstalledApps()
    {
        var pm = PackageManager;
        var packages = pm.GetInstalledPackages(PackageInfoFlags.RequestedPermissions);
        var list = new List<string>();

        string enabledAccessibility = Settings.Secure.GetString(ContentResolver, Settings.Secure.EnabledAccessibilityServices) ?? string.Empty;

        string[] dangerous = new[] {
            Android.Manifest.Permission.ReadSms,
            Android.Manifest.Permission.ReadContacts,
            Android.Manifest.Permission.CallPhone,
            Android.Manifest.Permission.RecordAudio,
            Android.Manifest.Permission.WriteExternalStorage,
            Android.Manifest.Permission.ReadExternalStorage,
            Android.Manifest.Permission.Camera,
            Android.Manifest.Permission.AccessFineLocation,
            Android.Manifest.Permission.ReadCallLog,
            Android.Manifest.Permission.SendSms
        };

        foreach (var pkg in packages)
        {
            try
            {
                var label = pkg.ApplicationInfo.LoadLabel(pm);
                var installer = pm.GetInstallerPackageName(pkg.PackageName) ?? "غير معروف";
                var sb = new System.Text.StringBuilder();
                sb.Append(label).Append(" (" + pkg.PackageName + ")\n");
                sb.Append("مزود التثبيت: ").Append(installer).Append("\n");

                var risky = new List<string>();
                if (pkg.RequestedPermissions != null)
                {
                    foreach (var p in pkg.RequestedPermissions)
                    {
                        if (dangerous.Contains(p)) risky.Add(p);
                    }
                }

                if (risky.Count > 0) sb.Append("أذونات خطرة: ").Append(string.Join(", ", risky)).Append("\n");

                if (!string.IsNullOrEmpty(enabledAccessibility) && enabledAccessibility.Contains(pkg.PackageName))
                {
                    sb.Append("مفعل: خدمة الوصول (Accessibility)\n");
                }

                list.Add(sb.ToString());
            }
            catch (Exception ex)
            {
                // ignore per-package errors
            }
        }

        return list;
    }

    bool CheckRoot()
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
                "/system/xbin/daemonsu"
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

    List<string> CheckUnknownInstallers()
    {
        var pm = PackageManager;
        var packages = pm.GetInstalledPackages(0);
        var list = new List<string>();
        var known = new[] { "com.android.vending", "com.google.android.feedback", "com.amazon.venezia", "com.huawei.appmarket" };

        foreach (var pkg in packages)
        {
            try
            {
                var installer = pm.GetInstallerPackageName(pkg.PackageName);
                if (string.IsNullOrEmpty(installer) || !known.Contains(installer))
                {
                    var label = pkg.ApplicationInfo.LoadLabel(pm);
                    list.Add($"{label} ({pkg.PackageName}) — مثبت من: {installer ?? "غير معروف"}");
                }
            }
            catch { }
        }

        return list;
    }
}

