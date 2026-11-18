package fixtures.xmlscan;

import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Decision 0111: an XML file scans components too (applicationContext.xml), so the annotation's root doesn't tell
 * which are beans.
 */
@SpringBootApplication
class XmlScanApp {
}
