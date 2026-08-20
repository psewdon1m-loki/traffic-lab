package com.loki.trafficlab;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ConnectionParserTest {
    private static final String FIRST = "vless://11111111-2222-4333-8444-555555555555@192.0.2.10:8021?encryption=none&security=reality&type=tcp&sni=example.com&fp=chrome&pbk=test&sid=abcd#secure%20sh";

    @Test public void extractsMultipleLinksAndPreservesOrder() {
        List<String> links = ConnectionParser.extractLinks("notes\n- " + FIRST + "\n" + FIRST.replace("secure%20sh", "second"));
        assertEquals(2, links.size());
        assertTrue(links.get(0).endsWith("#secure%20sh"));
        assertTrue(links.get(1).endsWith("#second"));
    }

    @Test public void parsesRealityProfileWithoutExposingCredentialInDeclaredJson() throws Exception {
        ConnectionParser.Profile profile = ConnectionParser.parse(FIRST);
        assertEquals("192.0.2.10", profile.host);
        assertEquals(8021, profile.port);
        assertEquals("secure sh", profile.name);
        assertTrue(profile.declared().getBoolean("hasRealityCredential"));
        assertTrue(!profile.declared().toString().contains("11111111"));
    }

    @Test public void acceptsRawSpacesInsideFragment() {
        List<String> links = ConnectionParser.extractLinks(FIRST.replace("secure%20sh", "secure sh"));
        assertEquals(1, links.size());
        assertTrue(links.get(0).endsWith("#secure%20sh"));
    }

    @Test public void canonicalFingerprintMatchesDesktopV2Contract() throws Exception {
        assertEquals("f1568b5341baaddf", ConnectionParser.parse(FIRST).fingerprint());
    }

    @Test public void negativeControlsOnlyMutateParametersThatAuthenticateTheProfile() throws Exception {
        assertEquals(List.of("invalid-uuid", "invalid-short-id", "wrong-sni"),
                TrafficLabRunner.applicableNegativeControlNames(ConnectionParser.parse(FIRST)));

        String plain = "vless://11111111-2222-4333-8444-555555555555@192.0.2.10:443?encryption=none&security=none&type=tcp#plain";
        assertEquals(List.of("invalid-uuid"),
                TrafficLabRunner.applicableNegativeControlNames(ConnectionParser.parse(plain)));

        String noShortId = FIRST.replace("&sid=abcd", "");
        assertEquals(List.of("invalid-uuid", "wrong-sni"),
                TrafficLabRunner.applicableNegativeControlNames(ConnectionParser.parse(noShortId)));
    }
}
