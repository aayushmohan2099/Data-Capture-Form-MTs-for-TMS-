# main/management/commands/create_thematic_experts.py
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
import re

User = get_user_model()

class Command(BaseCommand):
    help = "Create thematic expert users from a provided list. Password for all users will be '1234'."

    RAW_DATA = """
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    Farm LH\tSatyajeet Shukla
    FNHW\tParul
    FNHW\tParul
    FNHW\tParul
    FNHW\tParul
    FNHW\tParul
    FNHW\tParul
    M&E\tSudheer
    M&E\tSudheer
    M&E\tSudheer
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MCLF\tAjay Kushwaha
    MF&FI\tPrachi
    MF&FI\tPrachi
    MF&FI\tPrachi
    Non Farm\tAcharya shekher
    Non Farm\tAcharya shekher
    NONFARM LH\tAcharya shekher
    NONFARM LH\tAcharya shekher
    SISD\tAjay pratap singh
    SISD\tAjay pratap singh
    SISD\tAjay pratap singh
    SISD\tAjay pratap singh
    SMCB\tKarunesh
    SMCB\tKarunesh
    SMCB\tKarunesh
    SMCB\tKarunesh
    SMCB\tKarunesh
    SMCB\tKarunesh
    SMCB\tKarunesh
    SMCB\tKarunesh
    SMCB\tKarunesh
    SMCB\tKarunesh
    SMCB\tKarunesh
    TNCB\tSudheer
    TNCB\tSudheer
    TNCB\tSudheer
    Fishery\tParul
    Fishery\tParul
    Fishery\tParul
    """

    DEFAULT_PASSWORD = "1234"

    def normalize_name(self, name):
        # lower, replace non allowed characters with dots, collapse dots, strip dots
        s = name.strip().lower()
        # replace & with 'and' (optional) or keep; we'll replace non-alphanum with dot
        s = re.sub(r'[^a-z0-9@.+\-]', '.', s)
        s = re.sub(r'\.+', '.', s)
        s = s.strip('.')
        return s

    def make_username(self, clean_name, suffix=None):
        # keep '@smmu' at the end; if suffix present insert before the '@'
        if suffix:
            return f"{clean_name}_{suffix}@smmu"
        return f"{clean_name}@smmu"

    def ensure_unique_username(self, base_clean_name):
        # try base, if exists append numeric suffix increasing
        candidate = self.make_username(base_clean_name)
        if not User.objects.filter(username=candidate).exists():
            return candidate
        # try suffixes
        i = 1
        while True:
            candidate = self.make_username(base_clean_name, suffix=i)
            if not User.objects.filter(username=candidate).exists():
                return candidate
            i += 1

    def handle(self, *args, **options):
        # parse RAW_DATA, extract second column (expert name)
        names = []
        for line in self.RAW_DATA.strip().splitlines():
            parts = line.strip().split('\t')
            if len(parts) >= 2:
                expert = parts[1].strip()
                if expert:
                    names.append(expert)
            else:
                # fallback: maybe separated by multiple spaces
                sp = line.strip().split()
                if len(sp) >= 2:
                    expert = " ".join(sp[1:])
                    names.append(expert)

        # deduplicate while preserving order
        seen = set()
        unique_names = []
        for n in names:
            if n not in seen:
                seen.add(n)
                unique_names.append(n)

        created = []
        exists = []
        for expert in unique_names:
            clean = self.normalize_name(expert)
            username = self.ensure_unique_username(clean)
            # check again just in case
            if User.objects.filter(username=username).exists():
                exists.append(username)
                self.stdout.write(self.style.NOTICE(f"Skipped existing username: {username}"))
                continue

            user = User(username=username, role='thematic_expert', is_active=True)
            user.set_password(self.DEFAULT_PASSWORD)
            # optional: do not set is_staff so they cannot access the admin by default
            user.is_staff = False
            user.save()
            created.append(username)
            self.stdout.write(self.style.SUCCESS(f"Created user: {username} (password='{self.DEFAULT_PASSWORD}')"))

        self.stdout.write(self.style.MIGRATE_HEADING("Summary"))
        self.stdout.write(f"Total unique experts found: {len(unique_names)}")
        self.stdout.write(f"Created: {len(created)}")
        self.stdout.write(f"Skipped (existing usernames): {len(exists)}")
        if created:
            self.stdout.write("Created usernames:")
            for u in created:
                self.stdout.write(f" - {u}")
