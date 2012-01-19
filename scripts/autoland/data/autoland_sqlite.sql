--
-- Table structure for table `branches`
--

DROP TABLE IF EXISTS `branches`;
CREATE TABLE `branches` (
  `id` INTEGER PRIMARY KEY,
  `name` text,
  `repo_url` text,
  `threshold` int(11) DEFAULT NULL,
  `status` text,
  UNIQUE(`name`)
) ;
--
-- Table structure for table `patch_sets`
--

DROP TABLE IF EXISTS `patch_sets`;
CREATE TABLE `patch_sets` (
  `id` INTEGER PRIMARY KEY,
  `bug_id` int(11) DEFAULT NULL,
  `patches` text,
  `author` text,
  `retries` int(11) DEFAULT NULL,
  `revision` text,
  `branch` text,
  `try_run` int(11) DEFAULT NULL,
  `creation_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `push_time` timestamp NULL DEFAULT NULL,
  `completion_time` timestamp NULL DEFAULT NULL
) ;

