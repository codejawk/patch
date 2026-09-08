/*
 * npu_fw_loader.c - NPU firmware image loader
 */

#include "npu_types.h"
#include <linux/firmware.h>

#define NPU_FW_HDR_MAGIC   0x4657494D
#define NPU_FW_MAX_SIZE    (16 * 1024 * 1024)

static int npu_fw_verify_header(const struct npu_fw_hdr *hdr, size_t len)
{
    if (len < sizeof(*hdr))
        return -EINVAL;

    if (hdr->magic != NPU_FW_HDR_MAGIC)
        return -EINVAL;

    return 0;
}

int npu_fw_load(struct npu_device *dev, const char *name)
{
    const struct firmware *fw;
    const struct npu_fw_hdr *hdr;
    int ret;

    ret = request_firmware(&fw, name, dev->dma_dev);
    if (ret)
        return ret;

    hdr = (const struct npu_fw_hdr *)fw->data;

    ret = npu_fw_verify_header(hdr, fw->size);
    if (ret)
        goto out;

    memcpy(dev->fw_window, fw->data + hdr->payload_off, hdr->payload_len);

    dev->fw_loaded = true;

out:
    release_firmware(fw);
    return ret;
}
