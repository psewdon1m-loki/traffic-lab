package com.loki.trafficlab;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.provider.Settings;
import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class MainActivity extends Activity implements TrafficLabService.Listener {
    private static final int REQUEST_PERMISSIONS = 41;
    private static final int REQUEST_SAVE_ZIP = 42;
    private final Handler timer = new Handler();

    private EditText connections;
    private TextView connectionCount;
    private TextView status;
    private TextView time;
    private ProgressBar progress;
    private Button start;
    private Button paste;
    private Button clear;
    private Button save;
    private Button share;
    private TrafficLabService service;
    private boolean bound;
    private ArrayList<String> pendingStart;
    private File latestZip;
    private TrafficLabService.State latestState;

    private final ServiceConnection serviceConnection = new ServiceConnection() {
        @Override public void onServiceConnected(ComponentName name, IBinder binder) {
            service = ((TrafficLabService.LocalBinder) binder).service(); bound = true; service.setListener(MainActivity.this);
            if (pendingStart != null) { ArrayList<String> copy = pendingStart; pendingStart = null; service.startTests(copy); }
        }
        @Override public void onServiceDisconnected(ComponentName name) { bound = false; service = null; }
    };

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        buildUi(); timer.post(tick);
    }

    @Override protected void onStart() {
        super.onStart(); bindService(new Intent(this, TrafficLabService.class), serviceConnection, Context.BIND_AUTO_CREATE);
    }

    @Override protected void onStop() {
        if (bound) { service.setListener(null); unbindService(serviceConnection); bound = false; }
        super.onStop();
    }

    @Override protected void onDestroy() { timer.removeCallbacks(tick); super.onDestroy(); }

    private void buildUi() {
        ScrollView scroll = new ScrollView(this); scroll.setFillViewport(true); scroll.setBackgroundColor(Color.rgb(245, 247, 251));
        LinearLayout root = new LinearLayout(this); root.setOrientation(LinearLayout.VERTICAL); root.setPadding(dp(20), dp(24), dp(20), dp(32));
        scroll.addView(root, new ScrollView.LayoutParams(-1, -2));

        TextView title = text("Loki Traffic Lab", 28, Color.rgb(25, 35, 61)); title.setTypeface(Typeface.DEFAULT_BOLD); root.addView(title);
        TextView subtitle = text("Android network and VLESS/REALITY diagnostic tester", 15, Color.rgb(82, 92, 116));
        subtitle.setPadding(0, dp(4), 0, dp(18)); root.addView(subtitle);

        LinearLayout card = card(); root.addView(card, params(-1, -2, 0, 0, 0, 16));
        TextView inputTitle = text("Connections", 18, Color.rgb(25, 35, 61)); inputTitle.setTypeface(Typeface.DEFAULT_BOLD); card.addView(inputTitle);
        TextView help = text("Copy one or many VLESS links as plain text. Links are tested sequentially and credentials are not written to reports.", 13, Color.DKGRAY);
        help.setPadding(0, dp(4), 0, dp(10)); card.addView(help);
        connections = new EditText(this); connections.setMinLines(5); connections.setGravity(Gravity.TOP | Gravity.START);
        connections.setHint("vless://…\nvless://…"); connections.setTextSize(13); connections.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE | InputType.TYPE_TEXT_VARIATION_URI);
        connections.setSaveEnabled(false); connections.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        connections.setHorizontallyScrolling(false); connections.setBackground(box(Color.WHITE, Color.rgb(205, 211, 225), 10)); connections.setPadding(dp(12), dp(10), dp(12), dp(10));
        card.addView(connections, params(-1, -2, 0, 0, 0, 10));
        connectionCount = text("0 connections ready", 13, Color.rgb(82, 92, 116)); card.addView(connectionCount);

        LinearLayout inputButtons = row(); card.addView(inputButtons, params(-1, -2, 0, 10, 0, 0));
        paste = button("Paste links from clipboard", false); inputButtons.addView(paste, params(0, dp(48), 1, 0, 6, 0));
        clear = button("Clear connections", true); inputButtons.addView(clear, params(0, dp(48), 1, 6, 0, 0));

        LinearLayout progressCard = card(); root.addView(progressCard, params(-1, -2, 0, 0, 0, 16));
        status = text("Ready. Active VPN will be checked before testing.", 15, Color.rgb(25, 35, 61)); status.setTypeface(Typeface.DEFAULT_BOLD); progressCard.addView(status);
        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal); progress.setMax(100); progress.setProgress(0);
        progressCard.addView(progress, params(-1, dp(18), 0, 12, 0, 6));
        time = text("Elapsed 00:00:00 · ETA --:--:--", 13, Color.rgb(82, 92, 116)); progressCard.addView(time);
        start = button("Start test", false); progressCard.addView(start, params(-1, dp(52), 0, 14, 0, 0));

        LinearLayout exportCard = card(); root.addView(exportCard, params(-1, -2, 0, 0, 0, 0));
        TextView resultTitle = text("Result export", 18, Color.rgb(25, 35, 61)); resultTitle.setTypeface(Typeface.DEFAULT_BOLD); exportCard.addView(resultTitle);
        TextView resultHelp = text("The ZIP stays in temporary app cache. Choose where to save it, or send it with the Android Sharesheet.", 13, Color.DKGRAY);
        resultHelp.setPadding(0, dp(4), 0, dp(10)); exportCard.addView(resultHelp);
        save = button("Save ZIP", false); share = button("Share ZIP", true); save.setEnabled(false); share.setEnabled(false);
        LinearLayout exportButtons = row(); exportButtons.addView(save, params(0, dp(48), 1, 0, 6, 0)); exportButtons.addView(share, params(0, dp(48), 1, 6, 0, 0)); exportCard.addView(exportButtons);

        paste.setOnClickListener(view -> pasteClipboard()); clear.setOnClickListener(view -> clearEverything());
        start.setOnClickListener(view -> startOrStop()); save.setOnClickListener(view -> saveZip()); share.setOnClickListener(view -> shareZip());
        connections.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            public void onTextChanged(CharSequence s, int start, int before, int count) { updateCount(); }
            public void afterTextChanged(Editable s) {}
        });
        setContentView(scroll); updateCount();
    }

    private void pasteClipboard() {
        ClipboardManager clipboard = getSystemService(ClipboardManager.class); ClipData clip = clipboard == null ? null : clipboard.getPrimaryClip();
        if (clip == null || clip.getItemCount() == 0) { toast("Clipboard is empty"); return; }
        StringBuilder raw = new StringBuilder();
        for (int i = 0; i < clip.getItemCount(); i++) { CharSequence value = clip.getItemAt(i).coerceToText(this); if (value != null) raw.append(value).append('\n'); }
        List<String> imported = ConnectionParser.extractLinks(raw.toString());
        if (imported.isEmpty()) { toast("No vless:// links found in clipboard text"); return; }
        List<String> combined = ConnectionParser.extractLinks(connections.getText().toString()); combined.addAll(imported);
        connections.setText(String.join("\n", combined)); connections.setSelection(connections.length());
        toast("Imported " + imported.size() + " connection(s)");
    }

    private void startOrStop() {
        if (latestState != null && latestState.running()) {
            new AlertDialog.Builder(this).setTitle("Stop testing early?")
                    .setMessage("This is an emergency stop. The current temporary result will not be exported.")
                    .setNegativeButton("Continue testing", null).setPositiveButton("Stop", (dialog, which) -> { if (service != null) service.cancelTests(); }).show();
            return;
        }
        ArrayList<String> links = new ArrayList<>(ConnectionParser.extractLinks(connections.getText().toString()));
        if (links.isEmpty()) { toast("Paste at least one vless:// connection"); return; }
        if (AndroidNetworkDiagnostics.hasActiveVpn(this)) {
            new AlertDialog.Builder(this).setTitle("Active VPN detected")
                    .setMessage("Disable the active VPN or proxy tunnel before testing so the direct baseline is valid, then return and press Start test again.")
                    .setNegativeButton("Cancel", null)
                    .setPositiveButton("Open VPN settings", (dialog, which) -> {
                        try { startActivity(new Intent(Settings.ACTION_VPN_SETTINGS)); } catch (Exception error) { startActivity(new Intent(Settings.ACTION_WIRELESS_SETTINGS)); }
                    }).show();
            return;
        }
        pendingStart = links;
        List<String> missing = missingPermissions();
        if (!missing.isEmpty()) requestPermissions(missing.toArray(new String[0]), REQUEST_PERMISSIONS); else beginPendingTest();
    }

    private List<String> missingPermissions() {
        List<String> values = new ArrayList<>();
        if (checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) != PackageManager.PERMISSION_GRANTED) values.add(Manifest.permission.ACCESS_COARSE_LOCATION);
        if (checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) values.add(Manifest.permission.ACCESS_FINE_LOCATION);
        if (checkSelfPermission(Manifest.permission.READ_PHONE_STATE) != PackageManager.PERMISSION_GRANTED) values.add(Manifest.permission.READ_PHONE_STATE);
        if (Build.VERSION.SDK_INT >= 33) {
            if (checkSelfPermission(Manifest.permission.NEARBY_WIFI_DEVICES) != PackageManager.PERMISSION_GRANTED) values.add(Manifest.permission.NEARBY_WIFI_DEVICES);
            if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) values.add(Manifest.permission.POST_NOTIFICATIONS);
        }
        return values;
    }

    @Override public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == REQUEST_PERMISSIONS) beginPendingTest();
    }

    private void beginPendingTest() {
        if (pendingStart == null) return;
        Intent intent = new Intent(this, TrafficLabService.class);
        startForegroundService(intent);
        if (bound && service != null) { ArrayList<String> copy = pendingStart; pendingStart = null; service.startTests(copy); }
        else bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE);
    }

    private void saveZip() {
        if (latestZip == null || !latestZip.isFile()) { toast("No result ZIP is available"); return; }
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("application/zip");
        intent.putExtra(Intent.EXTRA_TITLE, latestZip.getName()); startActivityForResult(intent, REQUEST_SAVE_ZIP);
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQUEST_SAVE_ZIP || resultCode != RESULT_OK || data == null || data.getData() == null || latestZip == null) return;
        try (FileInputStream input = new FileInputStream(latestZip); OutputStream output = getContentResolver().openOutputStream(data.getData(), "w")) {
            if (output == null) throw new IllegalStateException("Selected destination is not writable");
            byte[] buffer = new byte[64 * 1024]; int read; while ((read = input.read(buffer)) >= 0) if (read > 0) output.write(buffer, 0, read);
            output.flush(); toast("ZIP saved");
        } catch (Exception error) { toast("Save failed: " + error.getClass().getSimpleName()); }
    }

    private void shareZip() {
        if (latestZip == null || !latestZip.isFile()) { toast("No result ZIP is available"); return; }
        Uri uri = Uri.parse("content://" + getPackageName() + ".results/latest.zip");
        Intent send = new Intent(Intent.ACTION_SEND).setType("application/zip").putExtra(Intent.EXTRA_STREAM, uri)
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        send.setClipData(ClipData.newRawUri("Traffic Lab result", uri));
        startActivity(Intent.createChooser(send, "Share Traffic Lab result"));
    }

    private void clearEverything() {
        if (latestState != null && latestState.running()) { toast("Stop the active test before clearing connections"); return; }
        connections.setText(""); latestZip = null; save.setEnabled(false); share.setEnabled(false);
        if (service != null) service.clearConnectionsAndResult();
        status.setText("Connection list and temporary result cleared"); progress.setProgress(0);
    }

    @Override public void onState(TrafficLabService.State state) {
        runOnUiThread(() -> render(state));
    }

    private void render(TrafficLabService.State state) {
        latestState = state; progress.setProgress(state.percent); status.setText(state.message + (state.total > 0 ? " · " + state.completed + "/" + state.total : ""));
        boolean running = state.running(); connections.setEnabled(!running); paste.setEnabled(!running); clear.setEnabled(!running);
        start.setText(running ? "Stop test" : "Start test"); latestZip = state.zip;
        save.setEnabled(state.completed() && latestZip != null && latestZip.isFile()); share.setEnabled(save.isEnabled());
        updateTime();
    }

    private final Runnable tick = new Runnable() {
        @Override public void run() { updateTime(); timer.postDelayed(this, 1000); }
    };

    private void updateTime() {
        TrafficLabService.State state = latestState;
        if (state == null || state.startedAtMs == 0) { time.setText("Elapsed 00:00:00 · ETA --:--:--"); return; }
        long elapsed = state.running() ? System.currentTimeMillis() - state.startedAtMs : state.durationMs;
        long eta = state.running() && state.percent > 2 ? elapsed * (100L - state.percent) / state.percent : -1;
        time.setText("Elapsed " + duration(elapsed) + " · ETA " + (eta < 0 ? "--:--:--" : duration(eta)));
    }

    private void updateCount() {
        int count = ConnectionParser.extractLinks(connections == null ? "" : connections.getText().toString()).size();
        connectionCount.setText(count + (count == 1 ? " connection ready" : " connections ready"));
    }

    private LinearLayout card() {
        LinearLayout value = new LinearLayout(this); value.setOrientation(LinearLayout.VERTICAL); value.setPadding(dp(16), dp(16), dp(16), dp(16));
        value.setBackground(box(Color.WHITE, Color.rgb(224, 228, 238), 14)); return value;
    }

    private LinearLayout row() { LinearLayout value = new LinearLayout(this); value.setOrientation(LinearLayout.HORIZONTAL); return value; }
    private TextView text(String value, int sp, int color) { TextView view = new TextView(this); view.setText(value); view.setTextSize(sp); view.setTextColor(color); return view; }

    private Button button(String label, boolean secondary) {
        Button button = new Button(this); button.setText(label); button.setTextSize(13); button.setAllCaps(false);
        button.setTextColor(secondary ? Color.rgb(49, 87, 213) : Color.WHITE);
        button.setBackground(box(secondary ? Color.WHITE : Color.rgb(49, 87, 213), Color.rgb(49, 87, 213), 10)); return button;
    }

    private GradientDrawable box(int fill, int stroke, int radiusDp) {
        GradientDrawable value = new GradientDrawable(); value.setColor(fill); value.setCornerRadius(dp(radiusDp)); value.setStroke(dp(1), stroke); return value;
    }

    private LinearLayout.LayoutParams params(int width, int height, float weight, int top, int right, int bottom) {
        LinearLayout.LayoutParams value = new LinearLayout.LayoutParams(width, height, weight); value.setMargins(0, dp(top), dp(right), dp(bottom)); return value;
    }

    private int dp(int value) { return Math.round(value * getResources().getDisplayMetrics().density); }
    private void toast(String value) { Toast.makeText(this, value, Toast.LENGTH_LONG).show(); }
    private static String duration(long ms) { long s = Math.max(0, ms / 1000); return String.format(Locale.ROOT, "%02d:%02d:%02d", s / 3600, s / 60 % 60, s % 60); }
}
