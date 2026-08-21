from django.core.management.base import BaseCommand
from django.core.cache import cache
import shutil
import os
from django.conf import settings

class Command(BaseCommand):
    help = 'Clears all rate limiting throttle cache state'

    def handle(self, *args, **options):
        try:
            cache.clear()
            self.stdout.write(self.style.SUCCESS('Successfully cleared Django cache memory.'))
        except Exception as e:
            self.stdout.write(self.style.WARNING(f'Cache clear attempt: {e}'))

        cache_dir = getattr(settings, 'CACHES', {}).get('default', {}).get('LOCATION')
        if cache_dir and os.path.exists(cache_dir):
            try:
                for item in os.listdir(cache_dir):
                    item_path = os.path.join(cache_dir, item)
                    if os.path.isfile(item_path):
                        os.unlink(item_path)
                    elif os.path.isdir(item_path):
                        shutil.rmtree(item_path)
                self.stdout.write(self.style.SUCCESS(f'Successfully cleared cache directory: {cache_dir}'))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'Failed to clear cache dir {cache_dir}: {e}'))
        else:
            self.stdout.write(self.style.SUCCESS('Cache directory cleared.'))
