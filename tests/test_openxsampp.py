import glob
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_modeler.graph import normalize_config
from threat_modeler.openxsampp import generate_openxsampp, parse_openxsampp

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_OXPP = sorted(glob.glob(os.path.join(ROOT, "*.openxsampp.xml")))
OXPP = _OXPP[0] if _OXPP else None


@unittest.skipIf(OXPP is None, "no OpenXSAM++ example present")
class TestOpenXSAMppRoundTrip(unittest.TestCase):
    def setUp(self):
        with open(OXPP, encoding="utf-8") as fh:
            self.model, self.config = parse_openxsampp(fh.read())

    def test_regenerate_round_trip_is_stable(self):
        # parse -> generate -> parse must preserve topology, layout and config.
        xml = generate_openxsampp(self.model, self.config)
        model2, config2 = parse_openxsampp(xml)

        self.assertEqual(len(model2.nodes), len(self.model.nodes))
        self.assertEqual(len(model2.edges), len(self.model.edges))

        by_id = {n.guid: n for n in self.model.nodes}
        for n in model2.nodes:
            src = by_id[n.guid]
            self.assertEqual((n.x, n.y, n.w, n.h), (src.x, src.y, src.w, src.h))

        c1, c2 = normalize_config(self.config), normalize_config(config2)
        self.assertEqual(set(c1), set(c2))
        for eid, fields in c1.items():
            self.assertEqual(fields, c2[eid])

    def test_rejects_non_openxsampp(self):
        with self.assertRaises(ValueError):
            parse_openxsampp("<not><openxsampp>")


if __name__ == "__main__":
    unittest.main(verbosity=2)
