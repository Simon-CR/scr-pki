import os
import glob
import shutil
import subprocess
import tarfile
from datetime import datetime
from typing import List, Dict, Optional
from fastapi import HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.core.config import settings

class BackupService:
    BACKUP_DIR = "/app/backups"
    MAX_BACKUPS = 5

    @classmethod
    def _get_db_env(cls) -> Dict[str, str]:
        env = os.environ.copy()
        env["PGPASSWORD"] = settings.DB_PASSWORD
        return env

    @classmethod
    def list_backups(cls) -> List[Dict]:
        if not os.path.exists(cls.BACKUP_DIR):
            return []
        
        files = glob.glob(os.path.join(cls.BACKUP_DIR, "pki_backup_*.tar.gz"))
        backups = []
        for f in files:
            stat = os.stat(f)
            backups.append({
                "filename": os.path.basename(f),
                "size": stat.st_size,
                "created_at": datetime.fromtimestamp(stat.st_mtime).isoformat()
            })
        
        # Sort by creation time descending
        return sorted(backups, key=lambda x: x["created_at"], reverse=True)

    @classmethod
    def create_backup(cls) -> Dict:
        os.makedirs(cls.BACKUP_DIR, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"pki_backup_{timestamp}.tar.gz"
        filepath = os.path.join(cls.BACKUP_DIR, filename)
        temp_dir = os.path.join(cls.BACKUP_DIR, f"temp_{timestamp}")
        
        try:
            os.makedirs(temp_dir)
            
            # 1. Dump Database
            # We create two dumps: one for Vault data, one for Application data
            # This allows for granular restores
            
            # Dump Vault Data (vault_kv_store)
            vault_dump = os.path.join(temp_dir, "vault_dump.sql")
            cmd_vault = [
                "pg_dump",
                "-h", settings.DB_HOST,
                "-p", str(settings.DB_PORT),
                "-U", settings.DB_USER,
                "-d", settings.DB_NAME,
                "-t", "vault_kv_store",  # Only this table
                "-c",                    # Include DROP TABLE
                "--if-exists",           # DROP TABLE IF EXISTS
                "-f", vault_dump
            ]
            subprocess.run(cmd_vault, env=cls._get_db_env(), check=True)

            # Dump App Data (everything else)
            app_dump = os.path.join(temp_dir, "app_dump.sql")
            cmd_app = [
                "pg_dump",
                "-h", settings.DB_HOST,
                "-p", str(settings.DB_PORT),
                "-U", settings.DB_USER,
                "-d", settings.DB_NAME,
                "-T", "vault_kv_store",  # Exclude this table
                "-c",                    # Include DROP TABLE
                "--if-exists",           # DROP TABLE IF EXISTS
                "-f", app_dump
            ]
            subprocess.run(cmd_app, env=cls._get_db_env(), check=True)
            
            # Legacy support: Create a full dump as well for older versions or manual use
            # (Optional, but good for safety. We won't use it in new restore logic if split exists)
            full_dump = os.path.join(temp_dir, "db_dump.sql")
            cmd_full = [
                "pg_dump",
                "-h", settings.DB_HOST,
                "-p", str(settings.DB_PORT),
                "-U", settings.DB_USER,
                "-d", settings.DB_NAME,
                "-f", full_dump
            ]
            subprocess.run(cmd_full, env=cls._get_db_env(), check=True)
            
            # 2. Copy Certificates (Static files)
            certs_dir = "/app/certs"
            if os.path.exists(certs_dir):
                shutil.copytree(certs_dir, os.path.join(temp_dir, "certs"))
            
            # 3. Create Archive
            with tarfile.open(filepath, "w:gz") as tar:
                tar.add(temp_dir, arcname=".")
                
            # 4. Prune old backups
            cls._prune_backups()
            
            return {
                "filename": filename,
                "message": "Backup created successfully"
            }
            
        except subprocess.CalledProcessError as e:
            raise HTTPException(status_code=500, detail=f"Database dump failed: {str(e)}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Backup failed: {str(e)}")
        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)

    @classmethod
    def restore_backup(cls, filename: str, db: Session, restore_app: bool = True, restore_vault: bool = True):
        filepath = os.path.join(cls.BACKUP_DIR, filename)
        if not os.path.exists(filepath):
            raise HTTPException(status_code=404, detail="Backup file not found")
            
        temp_dir = os.path.join(cls.BACKUP_DIR, f"restore_temp_{datetime.now().timestamp()}")
        
        try:
            os.makedirs(temp_dir)
            
            # 1. Extract Archive
            with tarfile.open(filepath, "r:gz") as tar:
                tar.extractall(temp_dir)
            
            # Check for split dumps (New Format)
            vault_dump = os.path.join(temp_dir, "vault_dump.sql")
            app_dump = os.path.join(temp_dir, "app_dump.sql")
            has_split_dumps = os.path.exists(vault_dump) and os.path.exists(app_dump)
            
            # Legacy Dump (Old Format)
            legacy_dump = os.path.join(temp_dir, "db_dump.sql")
            
            # 2. Restore Database
            if has_split_dumps:
                # New Granular Restore
                
                # Terminate other connections to allow drops
                try:
                    db.execute(text(f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND datname = '{settings.DB_NAME}'"))
                    db.commit()
                except Exception as e:
                    db.rollback()
                    # Continue, might fail if locks exist
                
                env = cls._get_db_env()
                base_cmd = [
                    "psql",
                    "-h", settings.DB_HOST,
                    "-p", str(settings.DB_PORT),
                    "-U", settings.DB_USER,
                    "-d", settings.DB_NAME
                ]

                if restore_app:
                    # Restore App Data
                    # app_dump.sql contains DROP TABLE IF EXISTS for app tables
                    result = subprocess.run(base_cmd + ["-f", app_dump], env=env, capture_output=True, text=True)
                    if result.returncode != 0:
                        raise Exception(f"App Data Import failed: {result.stderr}")
                        
                if restore_vault:
                    # Restore Vault Data
                    # vault_dump.sql contains DROP TABLE IF EXISTS vault_kv_store
                    result = subprocess.run(base_cmd + ["-f", vault_dump], env=env, capture_output=True, text=True)
                    if result.returncode != 0:
                        raise Exception(f"Vault Data Import failed: {result.stderr}")

            elif os.path.exists(legacy_dump):
                # Legacy Full Restore
                if not restore_app or not restore_vault:
                    raise HTTPException(status_code=400, detail="This backup is in an old format and only supports full system restore.")
                
                # Terminate other connections and reset schema
                try:
                    db.execute(text(f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND datname = '{settings.DB_NAME}'"))
                    db.execute(text("DROP SCHEMA public CASCADE"))
                    db.execute(text("CREATE SCHEMA public"))
                    db.execute(text(f"GRANT ALL ON SCHEMA public TO {settings.DB_USER}"))
                    db.commit()
                except Exception as e:
                    db.rollback()
                    raise Exception(f"Schema reset failed: {str(e)}")
                
                # Import dump
                restore_cmd = [
                    "psql",
                    "-h", settings.DB_HOST,
                    "-p", str(settings.DB_PORT),
                    "-U", settings.DB_USER,
                    "-d", settings.DB_NAME,
                    "-f", legacy_dump
                ]
                result = subprocess.run(restore_cmd, env=cls._get_db_env(), capture_output=True, text=True)
                if result.returncode != 0:
                    raise Exception(f"Import failed: {result.stderr}")
            else:
                raise HTTPException(status_code=400, detail="Invalid backup: missing database dump")
            
            # 3. Restore Certificates (Only if restoring App Data)
            # Certificates on disk correspond to App Data (Certificate model)
            if restore_app:
                certs_src = os.path.join(temp_dir, "certs")
                if os.path.exists(certs_src):
                    certs_dst = "/app/certs"
                    if os.path.exists(certs_dst):
                        # Cannot remove mount point, so remove contents
                        for item in os.listdir(certs_dst):
                            item_path = os.path.join(certs_dst, item)
                            if os.path.isfile(item_path) or os.path.islink(item_path):
                                os.unlink(item_path)
                            elif os.path.isdir(item_path):
                                shutil.rmtree(item_path)
                        
                        # Copy new contents
                        shutil.copytree(certs_src, certs_dst, dirs_exist_ok=True)
                    else:
                        shutil.copytree(certs_src, certs_dst)
                
            return {"message": "Restore completed successfully"}
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Restore failed: {str(e)}")
        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)

    @classmethod
    def delete_backup(cls, filename: str):
        filepath = os.path.join(cls.BACKUP_DIR, filename)
        if os.path.exists(filepath):
            os.remove(filepath)
            return {"message": "Backup deleted"}
        raise HTTPException(status_code=404, detail="Backup not found")

    @classmethod
    def _prune_backups(cls):
        files = glob.glob(os.path.join(cls.BACKUP_DIR, "pki_backup_*.tar.gz"))
        files.sort(key=os.path.getmtime, reverse=True)
        
        if len(files) > cls.MAX_BACKUPS:
            for f in files[cls.MAX_BACKUPS:]:
                os.remove(f)

    @classmethod
    def get_backup_path(cls, filename: str) -> str:
        filepath = os.path.join(cls.BACKUP_DIR, filename)
        if not os.path.exists(filepath):
            raise HTTPException(status_code=404, detail="Backup not found")
        return filepath
