package com.company.incidentplatform.evidence;

import com.company.incidentplatform.error.ConflictException;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * Streams stored evidence to clamd using its INSTREAM protocol.
 */
@Component
@ConditionalOnProperty(
        prefix = "incident-platform.evidence",
        name = "scanner",
        havingValue = "clamav",
        matchIfMissing = true)
public class ClamAvEvidenceScanner implements EvidenceScanner {

    private static final Logger log = LoggerFactory.getLogger(ClamAvEvidenceScanner.class);
    private static final String ENGINE = "clamd";
    private static final int CHUNK_SIZE = 64 * 1024;
    private static final int MAX_RESPONSE_BYTES = 4096;

    private final EvidenceStorage storage;
    private final long maxFileSizeBytes;
    private final String host;
    private final int port;
    private final int connectTimeoutMillis;
    private final int readTimeoutMillis;

    public ClamAvEvidenceScanner(
            EvidenceStorage storage,
            EvidenceProperties properties,
            @Value("${incident-platform.evidence.clamav.host:localhost}") String host,
            @Value("${incident-platform.evidence.clamav.port:3310}") int port,
            @Value("${incident-platform.evidence.clamav.connect-timeout-ms:3000}") int connectTimeoutMillis,
            @Value("${incident-platform.evidence.clamav.read-timeout-ms:30000}") int readTimeoutMillis) {
        this.storage = storage;
        this.maxFileSizeBytes = properties.getMaxFileSizeBytes();
        this.host = host;
        this.port = port;
        this.connectTimeoutMillis = connectTimeoutMillis;
        this.readTimeoutMillis = readTimeoutMillis;
    }

    @Override
    public Verdict scan(String fileName, String storagePath, String contentType) {
        try (InputStream content = storage.open(storagePath);
                Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), connectTimeoutMillis);
            socket.setSoTimeout(readTimeoutMillis);

            try (DataOutputStream output = new DataOutputStream(socket.getOutputStream());
                    DataInputStream input = new DataInputStream(socket.getInputStream())) {
                output.write("zINSTREAM\0".getBytes(StandardCharsets.US_ASCII));
                output.flush();
                streamContent(content, output);
                output.writeInt(0);
                output.flush();

                return interpretResponse(readResponse(input));
            }
        } catch (IOException | ConflictException failure) {
            log.error("ClamAV scan failed for evidence object {}", storagePath, failure);
            return Verdict.failed(ENGINE, "ClamAV scan could not be completed: " + failure.getMessage());
        }
    }

    private void streamContent(InputStream content, DataOutputStream output) throws IOException {
        byte[] buffer = new byte[CHUNK_SIZE];
        long bytesSent = 0;
        int read;
        while ((read = content.read(buffer)) != -1) {
            if (read == 0) {
                continue;
            }
            bytesSent += read;
            if (bytesSent > maxFileSizeBytes) {
                throw new IOException("Stored evidence exceeds the configured ClamAV scan size limit");
            }
            output.writeInt(read);
            output.write(buffer, 0, read);
        }
    }

    private static String readResponse(DataInputStream input) throws IOException {
        ByteArrayOutputStream response = new ByteArrayOutputStream();
        int value;
        while ((value = input.read()) != 0) {
            if (value == -1) {
                throw new IOException("ClamAV closed the connection before returning a complete response");
            }
            if (response.size() >= MAX_RESPONSE_BYTES) {
                throw new IOException("ClamAV returned an oversized response");
            }
            response.write(value);
        }
        return response.toString(StandardCharsets.US_ASCII).trim();
    }

    private static Verdict interpretResponse(String response) {
        if (response.equals("stream: OK")) {
            return Verdict.clean(ENGINE);
        }

        if (response.startsWith("stream: ") && response.endsWith(" FOUND")) {
            String signature = response.substring("stream: ".length(), response.length() - " FOUND".length()).trim();
            if (!signature.isEmpty()) {
                return Verdict.quarantined(
                        ENGINE,
                        signature,
                        "ClamAV detected malware signature: " + signature);
            }
        }

        String detail = response.isBlank()
                ? "ClamAV returned an empty or malformed response"
                : "ClamAV could not complete the scan: " + response;
        return Verdict.failed(ENGINE, detail);
    }
}
