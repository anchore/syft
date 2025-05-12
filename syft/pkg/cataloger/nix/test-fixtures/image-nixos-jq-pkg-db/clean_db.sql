-- Delete DerivationOutputs where path is not in RequiredPaths
DELETE FROM DerivationOutputs
WHERE path NOT IN (SELECT path FROM RequiredPaths);

-- Delete ValidPaths where path is not in RequiredPaths
DELETE FROM ValidPaths
WHERE path NOT IN (SELECT path FROM RequiredPaths);

DELETE FROM Refs
WHERE referrer NOT IN (SELECT id FROM ValidPaths WHERE path IN (SELECT path FROM RequiredPaths))
   OR reference NOT IN (SELECT id FROM ValidPaths WHERE path IN (SELECT path FROM RequiredPaths));


-- Run VACUUM to clean up the database file
VACUUM;