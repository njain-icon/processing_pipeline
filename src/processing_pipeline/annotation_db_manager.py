"""
MS SQL Server Database Manager for Thrift Annotations

This module provides database operations for storing and retrieving
AnnotationData objects as JSON in MS SQL Server.
"""

import sys
import json
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

import pyodbc
import yaml

from config_encryption import encrypt_password, decrypt_password, is_encrypted_password

sys.path.insert(0, 'gen-py')
from Annotations.ttypes import AnnotationData, Annotation

from thrift.protocol import TJSONProtocol
from thrift.transport import TTransport


class AnnotationDBManager:
    """Manages database operations for AnnotationData objects."""

    def __init__(self, config_path: str = "db_config.yaml"):
        """
        Initialize the database manager.

        Args:
            config_path: Path to the YAML configuration file
        """
        self.config = self._load_config(config_path)
        self.table_name = self.config['database']['table_name']
        self.history_table_name = self.config['database'].get('annotation_history_table')
        self._setup_logging()
        self.logger.info(
            f"Initialized AnnotationDBManager with table: {self.table_name}, "
            f"history_table: {self.history_table_name}"
        )

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """
        Load configuration from YAML file.

        Automatically encrypts plaintext passwords on first use.
        If a plaintext 'password' field is found in the database config,
        it will be encrypted and saved as 'default_hash_id', and the
        plaintext field will be removed from the YAML file.
        """
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)

            # Auto-migration: Encrypt plaintext password if found
            db_config = config.get('database', {})
            auth_method = db_config.get('auth_method', 'sql').lower()

            # Only process password for SQL Server authentication
            if auth_method == 'sql':
                has_plaintext = 'password' in db_config
                has_encrypted = 'default_hash_id' in db_config

                if has_plaintext and not has_encrypted:
                    # Migrate: encrypt the plaintext password
                    plaintext_pwd = db_config['password']
                    encrypted_pwd = encrypt_password(plaintext_pwd)

                    # Update config in memory
                    db_config['default_hash_id'] = encrypted_pwd
                    del db_config['password']

                    # Save updated config to file
                    try:
                        with open(config_path, 'w') as f:
                            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
                        print(f"[Security] Encrypted password in {config_path}")
                        print(f"[Security] Plaintext password has been removed from config file")
                    except Exception as write_error:
                        # Log error but continue with in-memory encrypted version
                        print(f"[Warning] Failed to save encrypted password to {config_path}: {write_error}")
                        print(f"[Warning] Using encrypted password in memory only for this session")

                elif has_plaintext and has_encrypted:
                    # Both exist - prefer encrypted, log warning
                    print(f"[Warning] Both 'password' and 'default_hash_id' found in {config_path}")
                    print(f"[Warning] Using 'default_hash_id' (plaintext will be ignored)")
                    # Remove plaintext from memory
                    if 'password' in db_config:
                        del db_config['password']

                elif not has_plaintext and not has_encrypted:
                    # No password field at all
                    raise ValueError(
                        f"No password field found in {config_path}. "
                        f"For SQL Server authentication, provide either 'password' or 'default_hash_id'."
                    )

            return config

        except Exception as e:
            raise ValueError(f"Failed to load config from {config_path}: {e}")

    def _setup_logging(self):
        """Configure logging based on config settings."""
        log_config = self.config.get('logging', {})
        if log_config.get('enabled', True):
            level = getattr(logging, log_config.get('level', 'INFO'))
            logging.basicConfig(
                level=level,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        self.logger = logging.getLogger(__name__)

    def _get_connection_string(self) -> str:
        """Build SQL Server connection string from configuration."""
        db_config = self.config['database']

        # Use custom connection string if provided
        if 'connection_string' in db_config:
            return db_config['connection_string']

        # Build connection string from components
        driver = db_config.get('driver', 'ODBC Driver 17 for SQL Server')
        server = db_config['server']
        database = db_config['database']
        port = db_config.get('port', 1433)
        timeout = db_config.get('timeout', 30)

        conn_str = f"Driver={{{driver}}};Server={server},{port};Database={database};"
        conn_str += f"Connection Timeout={timeout};"

        # Add authentication
        auth_method = db_config.get('auth_method', 'sql').lower()
        if auth_method == 'windows':
            conn_str += "Trusted_Connection=yes;"
        else:  # SQL Server authentication
            username = db_config['username']

            # Decrypt password (default_hash_id field is set by _load_config)
            encrypted_pwd = db_config.get('default_hash_id')
            if not encrypted_pwd:
                raise ValueError(
                    "No default_hash_id found in database config. "
                    "The password should have been encrypted automatically."
                )

            try:
                password = decrypt_password(encrypted_pwd)
            except Exception as e:
                raise ValueError(
                    f"Failed to decrypt password: {e}. "
                    f"The encrypted password may be corrupted or was encrypted on a different machine."
                )

            conn_str += f"UID={username};PWD={password};"

        return conn_str

    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections.

        Yields:
            pyodbc.Connection: Active database connection

        Example:
            with manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM Annotations")
        """
        conn = None
        try:
            conn_str = self._get_connection_string()
            conn = pyodbc.connect(conn_str)
            self.logger.debug("Database connection established")
            yield conn
            conn.commit()
        except Exception as e:
            if conn:
                conn.rollback()
            self.logger.error(f"Database error: {e}")
            raise
        finally:
            if conn:
                conn.close()
                self.logger.debug("Database connection closed")

    @staticmethod
    def thrift_to_dict(obj: Any) -> Any:
        """
        Convert a Thrift object to a dictionary recursively.

        Args:
            obj: Thrift object (or primitive type)

        Returns:
            Dictionary representation or primitive value
        """
        if obj is None:
            return None

        # Handle primitives
        if isinstance(obj, (int, float, str, bool)):
            return obj

        # Handle lists
        if isinstance(obj, list):
            return [AnnotationDBManager.thrift_to_dict(item) for item in obj]

        # Handle sets
        if isinstance(obj, set):
            return list(obj)

        # Handle dictionaries
        if isinstance(obj, dict):
            return {k: AnnotationDBManager.thrift_to_dict(v) for k, v in obj.items()}

        # Handle Thrift objects (have __dict__)
        if hasattr(obj, '__dict__'):
            result = {}
            for key, value in obj.__dict__.items():
                # Skip private attributes
                if not key.startswith('_'):
                    result[key] = AnnotationDBManager.thrift_to_dict(value)
            return result

        # Default: try to convert to string
        return str(obj)

    @staticmethod
    def dict_to_annotation(data: Dict[str, Any]) -> Annotation:
        """
        Convert a dictionary back to an Annotation object.

        Args:
            data: Dictionary representation of an Annotation

        Returns:
            Annotation object
        """
        return Annotation(
            eType=data.get('eType'),
            dXPos=data.get('dXPos'),
            dYPos=data.get('dYPos'),
            dWidth=data.get('dWidth'),
            dHeight=data.get('dHeight'),
            sText=data.get('sText'),
            sFillColour=data.get('sFillColour'),
            sLineColour=data.get('sLineColour'),
            iRotation=data.get('iRotation'),
            dLineOpacity=data.get('dLineOpacity'),
            dFillOpacity=data.get('dFillOpacity'),
            dLineWidth=data.get('dLineWidth'),
            dFontHeight=data.get('dFontHeight'),
            sFontName=data.get('sFontName'),
            sFontColour=data.get('sFontColour'),
            iOrder=data.get('iOrder'),
            sCreatedBy=data.get('sCreatedBy', ""),
            sTimeCreated=data.get('sTimeCreated', ""),
            sModifiedBy=data.get('sModifiedBy', ""),
            sModifiedTime=data.get('sModifiedTime', ""),
            iPageLevelID=data.get('iPageLevelID'),
            bBold=data.get('bBold', False),
            bItalic=data.get('bItalic', False),
            dRotation=data.get('dRotation', 0.0),
            eAlign=data.get('eAlign', 0),
            lModifiedByID=data.get('lModifiedByID', 0),
            lCreatedByID=data.get('lCreatedByID', 0),
            bUnderline=data.get('bUnderline', False),
            lTextBottom=data.get('lTextBottom', 0),
            dOffsetRotation=data.get('dOffsetRotation', 0.0),
            bAutoWrap=data.get('bAutoWrap', False),
            sReasonCategory=data.get('sReasonCategory'),
            sFoundValue=data.get('sFoundValue'),
            sSearchedValue=data.get('sSearchedValue'),
            iConfidence=data.get('iConfidence'),
            eSource=data.get('eSource', 1),
            lFormFieldID=data.get('lFormFieldID')
        )

    @staticmethod
    def dict_to_annotation_data(data: Dict[str, Any]) -> AnnotationData:
        """
        Convert a dictionary back to an AnnotationData object.

        Args:
            data: Dictionary representation of AnnotationData

        Returns:
            AnnotationData object
        """
        # Convert annotation list
        annotations = None
        if data.get('aAnnots'):
            annotations = [
                AnnotationDBManager.dict_to_annotation(annot)
                for annot in data['aAnnots']
            ]

        return AnnotationData(
            aAnnots=annotations,
            iPageLevelIDCount=data.get('iPageLevelIDCount'),
            ePageBlocker=data.get('ePageBlocker', 0),
            sPageBlockerColour=data.get('sPageBlockerColour'),
            lPageNumber=data.get('lPageNumber')
        )

    def annotation_data_to_json(self, annot_data: AnnotationData) -> str:
        """
        Convert AnnotationData object to JSON string using Thrift JSON protocol.

        Args:
            annot_data: AnnotationData object

        Returns:
            JSON string representation in Thrift JSON format
        """
        transport = TTransport.TMemoryBuffer()
        protocol = TJSONProtocol.TJSONProtocol(transport)
        annot_data.write(protocol)
        return transport.getvalue().decode('utf-8')

    def json_to_annotation_data(self, json_str: str) -> AnnotationData:
        """
        Convert JSON string back to AnnotationData object using Thrift JSON protocol.

        Args:
            json_str: JSON string representation in Thrift JSON format

        Returns:
            AnnotationData object
        """
        transport = TTransport.TMemoryBuffer(json_str.encode('utf-8'))
        protocol = TJSONProtocol.TJSONProtocol(transport)
        annot_data = AnnotationData()
        annot_data.read(protocol)
        return annot_data

    def insert(
        self,
        annot_data: AnnotationData,
        object_id: int,
        field_id: int,
        set_id: int,
        lookup_info1: str,
        lookup_info2: str
    ) -> int:
        """
        Insert a new AnnotationData record into the database.

        Args:
            annot_data: AnnotationData object to store
            object_id: Object ID value
            field_id: Field ID value
            set_id: Set ID value
            lookup_info1: Lookup info string 1
            lookup_info2: Lookup info string 2

        Returns:
            The ID of the newly inserted record

        Raises:
            Exception: If insertion fails
        """
        json_data = self.annotation_data_to_json(annot_data)
        utc_now = datetime.now(timezone.utc)

        query = f"""
            INSERT INTO {self.table_name}
            (object_id, field_id, set_id, lookup_info1, lookup_info2, Updated, Annot_data)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                query,
                (object_id, field_id, set_id, lookup_info1, lookup_info2, utc_now, json_data)
            )

            # Get the inserted ID
            cursor.execute("SELECT @@IDENTITY AS ID")
            inserted_id = cursor.fetchone()[0]

            self.logger.info(
                f"Inserted record ID={inserted_id}, object_id={object_id}, "
                f"field_id={field_id}, set_id={set_id}"
            )

        # Save to history table after insert (full audit trail)
        # Called outside the transaction so the insert is committed first
        if self.history_table_name:
            try:
                self.save_to_history(int(inserted_id))
            except Exception as e:
                self.logger.warning(
                    f"Failed to save record ID={inserted_id} to history: {e}"
                )

        return int(inserted_id)

    def update(
        self,
        record_id: int,
        annot_data: Optional[AnnotationData] = None,
        object_id: Optional[int] = None,
        field_id: Optional[int] = None,
        set_id: Optional[int] = None,
        lookup_info1: Optional[str] = None,
        lookup_info2: Optional[str] = None
    ) -> bool:
        """
        Update an existing annotation record.

        Args:
            record_id: ID of the record to update
            annot_data: New AnnotationData object (if updating annotation data)
            object_id: New object ID (if updating)
            field_id: New field ID (if updating)
            set_id: New set ID (if updating)
            lookup_info1: New lookup info 1 (if updating)
            lookup_info2: New lookup info 2 (if updating)

        Returns:
            True if update successful, False if record not found

        Raises:
            Exception: If update fails
        """
        updates = []
        params = []

        if annot_data is not None:
            json_data = self.annotation_data_to_json(annot_data)
            updates.append("Annot_data = ?")
            params.append(json_data)

        if object_id is not None:
            updates.append("object_id = ?")
            params.append(object_id)

        if field_id is not None:
            updates.append("field_id = ?")
            params.append(field_id)

        if set_id is not None:
            updates.append("set_id = ?")
            params.append(set_id)

        if lookup_info1 is not None:
            updates.append("lookup_info1 = ?")
            params.append(lookup_info1)

        if lookup_info2 is not None:
            updates.append("lookup_info2 = ?")
            params.append(lookup_info2)

        if not updates:
            self.logger.warning("No updates specified")
            return False

        # Always update the Updated timestamp
        updates.append("Updated = ?")
        params.append(datetime.now(timezone.utc))

        # Add ID to params
        params.append(record_id)

        query = f"""
            UPDATE {self.table_name}
            SET {', '.join(updates)}
            WHERE ID = ?
        """

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows_affected = cursor.rowcount

        # Check if update was successful
        if rows_affected > 0:
            self.logger.info(f"Updated record ID={record_id}")

            # Save to history table after update
            # Called outside the transaction so the update is committed first
            if self.history_table_name:
                try:
                    self.save_to_history(record_id)
                except Exception as e:
                    self.logger.warning(
                        f"Failed to save updated record ID={record_id} to history: {e}"
                    )

            return True
        else:
            self.logger.warning(f"Record ID={record_id} not found")
            return False

    def read(self, record_id: int) -> Optional[Dict[str, Any]]:
        """
        Read a single annotation record by ID.

        Args:
            record_id: ID of the record to retrieve

        Returns:
            Dictionary containing all fields including deserialized AnnotationData,
            or None if not found
        """
        query = f"""
            SELECT ID, object_id, field_id, set_id, lookup_info1, lookup_info2,
                   Updated, Annot_data
            FROM {self.table_name}
            WHERE ID = ?
        """

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (record_id,))
            row = cursor.fetchone()

            if not row:
                self.logger.warning(f"Record ID={record_id} not found")
                return None

            result = {
                'ID': row.ID,
                'object_id': row.object_id,
                'field_id': row.field_id,
                'set_id': row.set_id,
                'lookup_info1': row.lookup_info1,
                'lookup_info2': row.lookup_info2,
                'Updated': row.Updated,
                'Annot_data_json': row.Annot_data,
                'Annot_data': self.json_to_annotation_data(row.Annot_data)
            }

            self.logger.info(f"Retrieved record ID={record_id}")
            return result

    def query(
        self,
        object_id: Optional[int] = None,
        field_id: Optional[int] = None,
        set_id: Optional[int] = None,
        lookup_info1: Optional[str] = None,
        lookup_info2: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Query annotation records with optional filters.

        Args:
            object_id: Filter by object ID
            field_id: Filter by field ID
            set_id: Filter by set ID
            lookup_info1: Filter by lookup info 1
            lookup_info2: Filter by lookup info 2
            limit: Maximum number of records to return

        Returns:
            List of dictionaries containing matching records
        """
        where_clauses = []
        params = []

        if object_id is not None:
            where_clauses.append("object_id = ?")
            params.append(object_id)

        if field_id is not None:
            where_clauses.append("field_id = ?")
            params.append(field_id)

        if set_id is not None:
            where_clauses.append("set_id = ?")
            params.append(set_id)

        if lookup_info1 is not None:
            where_clauses.append("lookup_info1 = ?")
            params.append(lookup_info1)

        if lookup_info2 is not None:
            where_clauses.append("lookup_info2 = ?")
            params.append(lookup_info2)

        query = f"""
            SELECT ID, object_id, field_id, set_id, lookup_info1, lookup_info2,
                   Updated, Annot_data
            FROM {self.table_name}
        """

        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)

        query += " ORDER BY ID DESC"

        if limit is not None:
            query += f" OFFSET 0 ROWS FETCH NEXT {limit} ROWS ONLY"

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)

            results = []
            for row in cursor.fetchall():
                results.append({
                    'ID': row.ID,
                    'object_id': row.object_id,
                    'field_id': row.field_id,
                    'set_id': row.set_id,
                    'lookup_info1': row.lookup_info1,
                    'lookup_info2': row.lookup_info2,
                    'Updated': row.Updated,
                    'Annot_data_json': row.Annot_data,
                    'Annot_data': self.json_to_annotation_data(row.Annot_data)
                })

            self.logger.info(f"Query returned {len(results)} records")
            return results

    def delete(self, record_id: int) -> bool:
        """
        Delete an annotation record by ID.

        Args:
            record_id: ID of the record to delete

        Returns:
            True if deletion successful, False if record not found

        Raises:
            Exception: If deletion fails
        """
        query = f"DELETE FROM {self.table_name} WHERE ID = ?"

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (record_id,))
            rows_affected = cursor.rowcount

            if rows_affected > 0:
                self.logger.info(f"Deleted record ID={record_id}")
                return True
            else:
                self.logger.warning(f"Record ID={record_id} not found for deletion")
                return False

    def delete_by_filters(
        self,
        object_id: Optional[int] = None,
        field_id: Optional[int] = None,
        set_id: Optional[int] = None
    ) -> int:
        """
        Delete annotation records matching specified filters.

        Args:
            object_id: Filter by object ID
            field_id: Filter by field ID
            set_id: Filter by set ID

        Returns:
            Number of records deleted

        Raises:
            Exception: If deletion fails
        """
        where_clauses = []
        params = []

        if object_id is not None:
            where_clauses.append("object_id = ?")
            params.append(object_id)

        if field_id is not None:
            where_clauses.append("field_id = ?")
            params.append(field_id)

        if set_id is not None:
            where_clauses.append("set_id = ?")
            params.append(set_id)

        if not where_clauses:
            raise ValueError("At least one filter must be specified for bulk delete")

        query = f"DELETE FROM {self.table_name} WHERE " + " AND ".join(where_clauses)

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows_affected = cursor.rowcount

            self.logger.info(f"Deleted {rows_affected} records")
            return rows_affected

    def save_to_history(self, record_id: int) -> Optional[int]:
        """
        Copy an annotation record to the history table.

        This implements the C++ QANInsertAnnotationHistory query pattern:
        - Copies the record from annotations table to history table
        - Sets userid=0 and username="System"
        - Sets MODIFIED timestamp to current UTC time

        Args:
            record_id: ID of the annotation record to copy to history

        Returns:
            The HISTID of the newly inserted history record, or None if source record not found

        Raises:
            ValueError: If history table is not configured
            Exception: If insertion fails
        """
        if not self.history_table_name:
            raise ValueError(
                "Annotation history table not configured. "
                "Add 'annotation_history_table' to database section in config file."
            )

        # Get the source record
        source_record = self.read(record_id)
        if not source_record:
            self.logger.warning(
                f"Cannot save to history: source record ID={record_id} not found"
            )
            return None

        utc_now = datetime.now(timezone.utc)

        # Insert into history table using the same lookup keys and annotation data
        # Matches C++ pattern: INSERT INTO history SELECT ... FROM annotations WHERE ...
        query = f"""
            INSERT INTO {self.history_table_name}
            (SET_ID, OBJECT_ID, FIELD_ID, LOOKUP_INFO1, LOOKUP_INFO2,
             USERID, USERNAME, ANNOT_DATA, MODIFIED)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                query,
                (
                    source_record['set_id'],
                    source_record['object_id'],
                    source_record['field_id'],
                    source_record['lookup_info1'],
                    source_record['lookup_info2'],
                    0,  # userid = 0 (System)
                    "System",  # username = "System"
                    source_record['Annot_data_json'],
                    utc_now
                )
            )

            # Get the inserted history ID
            cursor.execute("SELECT @@IDENTITY AS HISTID")
            hist_id = cursor.fetchone()[0]

            self.logger.info(
                f"Saved record ID={record_id} to history table as HISTID={hist_id}"
            )

            return int(hist_id)

    def upsert(
        self,
        annot_data: AnnotationData,
        object_id: int,
        field_id: int,
        set_id: int,
        lookup_info1: str,
        lookup_info2: str
    ) -> tuple[int, bool]:
        """
        Insert or update an annotation record with history tracking.

        This method implements "upsert" logic:
        - Queries for existing record by lookup keys
        - If exists: updates the record, then saves to history
        - If not exists: inserts new record, then saves to history

        Args:
            annot_data: AnnotationData object to store
            object_id: Object ID value
            field_id: Field ID value
            set_id: Set ID value
            lookup_info1: Lookup info string 1
            lookup_info2: Lookup info string 2

        Returns:
            Tuple of (record_id, was_new_insert)
            - record_id: The ID of the inserted/updated record
            - was_new_insert: True if new record was inserted, False if existing record was updated

        Raises:
            Exception: If operation fails
        """
        # Query for existing record
        existing_records = self.query(
            object_id=object_id,
            field_id=field_id,
            set_id=set_id,
            lookup_info1=lookup_info1,
            lookup_info2=lookup_info2,
            limit=1
        )

        if existing_records:
            # Update existing record
            record_id = existing_records[0]['ID']
            self.logger.info(
                f"Upsert: Found existing record ID={record_id}, updating..."
            )

            # Update the annotation data (update() handles history automatically)
            self.update(record_id, annot_data=annot_data)

            return (record_id, False)
        else:
            # Insert new record
            self.logger.info("Upsert: No existing record found, inserting new...")

            record_id = self.insert(
                annot_data=annot_data,
                object_id=object_id,
                field_id=field_id,
                set_id=set_id,
                lookup_info1=lookup_info1,
                lookup_info2=lookup_info2
            )

            # Note: insert() already calls save_to_history() internally

            return (record_id, True)
