package com.loki.trafficlab;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;

import java.io.File;
import java.io.FileNotFoundException;

public final class ResultFileProvider extends ContentProvider {
    @Override public boolean onCreate() { return true; }

    @Override public String getType(Uri uri) { return "application/zip"; }

    @Override public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if (!"r".equals(mode) && !"rt".equals(mode)) throw new FileNotFoundException("Read-only provider");
        File file = currentResult();
        if (file == null) throw new FileNotFoundException("No completed Traffic Lab result");
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Override public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        File file = currentResult();
        String[] columns = projection == null ? new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE} : projection;
        MatrixCursor cursor = new MatrixCursor(columns, 1); MatrixCursor.RowBuilder row = cursor.newRow();
        for (String column : columns) {
            if (OpenableColumns.DISPLAY_NAME.equals(column)) row.add(file == null ? "traffic-lab-results.zip" : file.getName());
            else if (OpenableColumns.SIZE.equals(column)) row.add(file == null ? 0L : file.length());
            else row.add(null);
        }
        return cursor;
    }

    @Override public int delete(Uri uri, String selection, String[] selectionArgs) { return 0; }
    @Override public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) { return 0; }
    @Override public Uri insert(Uri uri, ContentValues values) { return null; }

    private File currentResult() {
        if (getContext() == null) return null; File directory = new File(getContext().getCacheDir(), "results");
        File[] matches = directory.listFiles((dir, name) -> name.endsWith(".zip"));
        if (matches == null || matches.length == 0) return null; File newest = matches[0];
        for (File match : matches) if (match.lastModified() > newest.lastModified()) newest = match;
        try {
            String expected = directory.getCanonicalPath() + File.separator; String actual = newest.getCanonicalPath();
            return actual.startsWith(expected) ? newest : null;
        } catch (Exception ignored) { return null; }
    }
}
