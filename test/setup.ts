import { DOMParser, XMLSerializer } from "xmldom";
import * as XmlCore from "xml-core";

(global as any).DOMParser = DOMParser;
(global as any).XMLSerializer = XMLSerializer;

XmlCore.setNodeDependencies({
  DOMParser,
  XMLSerializer,
});
