import pytest
import config
import app.db_models as db_models

from app.utils.sslyze.grade_scan_result import grade_scan_result, Grades

# change default db
# config.TestConfig.force_database_connection_string = "../../../Downloads/DB/2021-06-22-production-sanitized.db"
# config.TestConfig.force_database_connection_string = "../../../Downloads/DB/2020-09-xx-benchmark-24-hours.db"

skip_grading = True

@pytest.mark.usefixtures("client_class")
@pytest.mark.skipif(skip_grading, reason="This is not primarily pipeline test and can be skipped to reduce test duration")
class TestSuiteScanScheduler:

    @classmethod
    def teardown_class(cls):
        config.TestConfig.force_database_connection_string = None

    def test_grading(self):

        grades = {}
        reasons = {}

        scan_results_simplified = db_models.db.session.query(db_models.ScanResultsSimplified).all()

        for scan_result_simplified in scan_results_simplified:

            scan_result = db_models.db.session.query(db_models.ScanResults) \
                .get(scan_result_simplified.scanresult_id)

            grade_name, reason_ = grade_scan_result(scan_result, scan_result_simplified)

            grades[grade_name] = grades.get(grade_name, 0) + 1

            for reason in reason_:
                reasons[reason] = reasons.get(reason, 0) + 1

        print(f"summary: {grades}")

        print("reasons")
        for reason in reasons:
            print(f"{reason}: {reasons[reason]}")
