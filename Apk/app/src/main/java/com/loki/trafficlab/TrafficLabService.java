package com.loki.trafficlab;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class TrafficLabService extends Service {
    static final String CHANNEL_ID = "traffic-lab-tests";
    private static final int NOTIFICATION_ID = 17041;

    interface Listener { void onState(State state); }

    static final class State {
        final String phase; final int percent; final int completed; final int total; final String message;
        final long startedAtMs; final long durationMs; final File zip; final boolean usable; final TrafficLabRunner.TestType testType;
        State(String phase, int percent, int completed, int total, String message, long startedAtMs, long durationMs, File zip, boolean usable, TrafficLabRunner.TestType testType) {
            this.phase = phase; this.percent = percent; this.completed = completed; this.total = total; this.message = message;
            this.startedAtMs = startedAtMs; this.durationMs = durationMs; this.zip = zip; this.usable = usable; this.testType = testType;
        }
        boolean running() { return "running".equals(phase); }
        boolean completed() { return "completed".equals(phase); }
    }

    final class LocalBinder extends Binder { TrafficLabService service() { return TrafficLabService.this; } }

    private final IBinder binder = new LocalBinder();
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private volatile State state = new State("idle", 0, 0, 0, "Ready", 0, 0, null, false, TrafficLabRunner.TestType.NORMAL);
    private volatile Listener listener;
    private volatile TrafficLabRunner runner;
    private PowerManager.WakeLock wakeLock;

    @Override public void onCreate() {
        super.onCreate();
        createNotificationChannel();
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        startForeground(NOTIFICATION_ID, notification("Preparing Traffic Lab", 0, 0, 0, true));
        return START_NOT_STICKY;
    }

    @Override public IBinder onBind(Intent intent) { return binder; }

    void setListener(Listener listener) { this.listener = listener; if (listener != null) listener.onState(state); }
    State state() { return state; }

    synchronized void startTests(List<String> connections) { startTests(connections, TrafficLabRunner.TestType.NORMAL); }

    synchronized void startTests(List<String> connections, TrafficLabRunner.TestType testType) {
        if (state.running()) return;
        if (testType == null) testType = TrafficLabRunner.TestType.NORMAL;
        final TrafficLabRunner.TestType selectedType = testType;
        ArrayList<String> copy = new ArrayList<>(connections);
        deleteTree(new File(getCacheDir(), "results"));
        long started = System.currentTimeMillis();
        update(new State("running", 0, 0, copy.size(), "Starting " + selectedType.value + " test", started, 0, null, false, selectedType));
        acquireWakeLock();
        runner = new TrafficLabRunner(this, (percent, completed, total, message) -> {
            long duration = Math.max(0, System.currentTimeMillis() - started);
            update(new State("running", percent, completed, total, message, started, duration, null, false, selectedType));
        });
        executor.submit(() -> {
            try {
                TrafficLabRunner.RunResult result = runner.run(copy, selectedType);
                copy.clear();
                update(new State("completed", 100, result.profileCount, result.profileCount,
                        result.usable ? selectedType.value + " testing completed successfully" : selectedType.value + " testing completed; no usable profile was confirmed",
                        started, result.durationMs, result.zip, result.usable, result.testType));
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt(); copy.clear();
                update(new State("canceled", state.percent, state.completed, state.total, "Testing canceled", started,
                        System.currentTimeMillis() - started, null, false, selectedType));
            } catch (Exception error) {
                copy.clear();
                update(new State("failed", state.percent, state.completed, state.total,
                        "Test failed: " + JsonUtil.redact(error.getClass().getSimpleName() + ": " + error.getMessage()), started,
                        System.currentTimeMillis() - started, null, false, selectedType));
            } finally {
                runner = null; releaseWakeLock();
                stopForeground(STOP_FOREGROUND_REMOVE);
            }
        });
    }

    synchronized void cancelTests() {
        TrafficLabRunner active = runner;
        if (active != null) active.cancel();
    }

    synchronized void clearConnectionsAndResult() {
        cancelTests();
        deleteTree(new File(getCacheDir(), "results"));
        state = new State("idle", 0, 0, 0, "Connection list and temporary result cleared", 0, 0, null, false, TrafficLabRunner.TestType.NORMAL);
        notifyListener();
        stopSelf();
    }

    @Override public void onDestroy() {
        cancelTests(); releaseWakeLock(); listener = null; executor.shutdownNow(); super.onDestroy();
    }

    private void update(State newState) {
        state = newState;
        if (newState.running()) {
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) manager.notify(NOTIFICATION_ID, notification(newState.message, newState.percent, newState.completed, newState.total, false));
        }
        notifyListener();
    }

    private void notifyListener() {
        Listener current = listener; if (current != null) current.onState(state);
    }

    private Notification notification(String message, int percent, int completed, int total, boolean indeterminate) {
        Intent launch = new Intent(this, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent pending = PendingIntent.getActivity(this, 0, launch, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Notification.Builder builder = new Notification.Builder(this, CHANNEL_ID);
        builder.setSmallIcon(android.R.drawable.stat_sys_download)
                .setContentTitle("Loki Traffic Lab")
                .setContentText(total > 0 ? completed + "/" + total + " · " + message : message)
                .setContentIntent(pending).setOngoing(true).setOnlyAlertOnce(true).setCategory(Notification.CATEGORY_PROGRESS)
                .setProgress(100, Math.max(0, Math.min(100, percent)), indeterminate);
        return builder.build();
    }

    private void createNotificationChannel() {
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager == null) return;
        NotificationChannel channel = new NotificationChannel(CHANNEL_ID, getString(R.string.notification_channel), NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("Progress for an explicitly started network test"); manager.createNotificationChannel(channel);
    }

    private void acquireWakeLock() {
        try {
            PowerManager manager = getSystemService(PowerManager.class);
            if (manager != null) {
                wakeLock = manager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "LokiTrafficLab::NetworkTest");
                wakeLock.acquire(2 * 60 * 60 * 1000L);
            }
        } catch (Exception ignored) {}
    }

    private void releaseWakeLock() {
        try { if (wakeLock != null && wakeLock.isHeld()) wakeLock.release(); } catch (Exception ignored) {} finally { wakeLock = null; }
    }

    private static void deleteTree(File target) {
        if (target == null || !target.exists()) return; File[] children = target.listFiles(); if (children != null) for (File child : children) deleteTree(child);
        //noinspection ResultOfMethodCallIgnored
        target.delete();
    }
}
