import pytest
import config
import app.db_models as db_models

from app.utils.sslyze.grade_scan_result import grade_scan_result, Grades

# change default db
config.TestConfig.force_database_connection_string = "test_db_sanitized.db"
config.TestConfig.force_create_tmp_db = False
# config.TestConfig.force_database_connection_string = "/Users/Mamo/Downloads/DBs-sanitized/2020-09-xx-benchmark-24-hours.db"


@pytest.mark.usefixtures("client_class")
class TestSuiteScanScheduler:

    def test_grading(self):

        print(f"db_path: {config.FlaskConfig.SQLALCHEMY_DATABASE_URI}")

        scan_results_simplified = db_models.db.session.query(
            db_models.ScanResultsSimplified
        ).all()

        tmp = db_models.db.session.query(db_models.Target).all()

        print(f"tmp: {tmp}")

        print(f"srs: {scan_results_simplified}")

        for scan_result_simplified in scan_results_simplified:
            scan_result = (
                db_models.db.session.query(db_models.ScanResults)
                .filter(
                    db_models.ScanResultsSimplified.scanresult_id
                    == scan_result_simplified.scanresult_id
                )
                .all()
            )
            assert len(scan_result) == 1
            grade_name, reason = grade_scan_result(scan_result[0], scan_result_simplified)
            print(f"grade: {grade_name}")
            # chain list obsahuje IDcka certifikatov, ktore si mozem nasplitovat


config.TestConfig.force_database_connection_string = None
