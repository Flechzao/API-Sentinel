package com.demo.vulnapp.controller;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.util.Map;

/**
 * #27 VULNERABLE: XML External Entity injection — external entities enabled.
 * #28 SAFE: external entities and DTDs disabled.
 */
@RestController
public class XxeController {

    /** #27: VULNERABLE — parses XML with external entities enabled (default). */
    @PostMapping(value = "/api/parse-xml", consumes = MediaType.APPLICATION_XML_VALUE)
    public Map<String, Object> parseXml(@RequestBody String xml) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            // Deliberately NOT disabling external entities
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xml)));
            NodeList nodes = doc.getDocumentElement().getChildNodes();
            StringBuilder content = new StringBuilder();
            for (int i = 0; i < nodes.getLength(); i++) {
                content.append(nodes.item(i).getTextContent());
            }
            return Map.of("parsed", content.toString());
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    /** #28: SAFE — disables DTDs and external entities completely. */
    @PostMapping(value = "/api/parse-config", consumes = MediaType.APPLICATION_XML_VALUE)
    public Map<String, Object> parseXmlSafe(@RequestBody String xml) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xml)));
            NodeList nodes = doc.getDocumentElement().getChildNodes();
            StringBuilder content = new StringBuilder();
            for (int i = 0; i < nodes.getLength(); i++) {
                content.append(nodes.item(i).getTextContent());
            }
            return Map.of("parsed", content.toString());
        } catch (Exception e) {
            return Map.of("error", "Rejected: " + e.getMessage());
        }
    }
}
